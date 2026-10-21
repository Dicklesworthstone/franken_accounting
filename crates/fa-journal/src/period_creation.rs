//! Authorized, immutable declarations of a fiscal year's period births.
//!
//! Period vertices and their limit cells are projections of one retained
//! SchemaControl. The control and every projection publish in the same
//! transaction; retry reads that declaration, never infers success from the
//! presence of one Period vertex. Book-scoped creation has no posting date.

use std::collections::BTreeMap;

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlKind, ControlPayload, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128,
    Reader, Writer, domain_digest, entry_mirrors,
};
use fa_policy::{Capability, Intent, Party, Reach};
use fa_time::{DateDay, PeriodDef, PeriodKind, PeriodState};
use fgdb::{Database, VertexRow, WriteBatch, WriteTxn, WriteTxnError};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::genesis::{BookContext, BookSpec, list_accounts};
use crate::limit::{LimitCell, LimitScope, period_cell_vid};
use crate::policy;
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, kind_tag, scalar_bytes, scalar_text};

/// Additive SchemaChange subkind; independent of the ControlPayload tag.
pub const SCHEMA_CHANGE_CREATE_PERIODS: u16 = 13;
const DOMAIN: &[u8; 21] = b"fa:period-creation:v1";

/// Canonical birth facts, before any subsequent period transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodCreation {
    pub calendar: String,
    pub fiscal_year: i32,
    pub periods: Vec<(PeriodDef, PeriodState)>,
}

impl PeriodCreation {
    pub fn from_spec(spec: &BookSpec, fiscal_year: i32) -> Result<Self, KernelError> {
        let classes = fa_registry::EntryClasses::embedded()
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        let matrix = fa_registry::Admissibility::embedded(&classes)
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        let pre_opening = matrix.pre_opening().ok_or_else(|| {
            KernelError::Corrupt("admissibility.toml has no pre_opening rule".into())
        })?;
        let mut periods = Vec::new();
        for mut definition in spec.calendar.periods_for_year(fiscal_year)? {
            let (kind, state) = spec.birth(&definition, pre_opening);
            definition.kind = kind;
            periods.push((definition, state));
        }
        Ok(Self {
            calendar: spec.calendar.id.clone(),
            fiscal_year,
            periods,
        })
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(DOMAIN).str(&self.calendar).i32(self.fiscal_year);
        w.list(&self.periods, |w, (period, state)| {
            w.str(&period.code)
                .i32(period.fiscal_year)
                .u16(period.ordinal)
                .u8(kind_tag(period.kind) as u8)
                .i32(period.start.0)
                .i32(period.end.0)
                .u8(state.tag());
        });
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn decode(raw: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(raw);
        let decode = |e: fa_model::DecodeError| KernelError::Model(e.into());
        if &r.fixed::<21>("period_creation.domain").map_err(decode)? != DOMAIN {
            return Err(corrupt("unknown birth-declaration format"));
        }
        let calendar = r
            .str(
                fa_model::limits::MAX_PERIOD_REF_BYTES,
                "period_creation.calendar",
            )
            .map_err(decode)?
            .to_string();
        let fiscal_year = r.i32("period_creation.fiscal_year").map_err(decode)?;
        // Thirteen normal periods, Opening/Closing, and at most four
        // adjustments is the largest calendar the current generator admits.
        let maximum = 13 + 2 + usize::from(fa_time::calendar::MAX_ADJUSTMENT_PERIODS);
        let periods = r
            .list(maximum, "period_creation.periods", |r| {
                let code = r.str(32, "period.code")?.to_string();
                let fiscal_year = r.i32("period.fiscal_year")?;
                let ordinal = r.u16("period.ordinal")?;
                let kind = match r.u8("period.kind")? {
                    0 => PeriodKind::Normal,
                    1 => PeriodKind::Adjustment,
                    2 => PeriodKind::Opening,
                    3 => PeriodKind::Closing,
                    4 => PeriodKind::Historical,
                    _ => return Err(r.invalid("period.kind")),
                };
                let start = DateDay(r.i32("period.start")?);
                let end = DateDay(r.i32("period.end")?);
                let state = PeriodState::from_tag(r.u8("period.born_state")?)
                    .ok_or_else(|| r.invalid("period.born_state"))?;
                if start >= end || !matches!(state, PeriodState::Future | PeriodState::Locked) {
                    return Err(r.invalid("period.birth"));
                }
                Ok((
                    PeriodDef {
                        code,
                        fiscal_year,
                        ordinal,
                        kind,
                        start,
                        end,
                    },
                    state,
                ))
            })
            .map_err(decode)?;
        r.finish().map_err(decode)?;
        if calendar.is_empty() || periods.is_empty() {
            return Err(corrupt("empty calendar or period declaration"));
        }
        let out = Self {
            calendar,
            fiscal_year,
            periods,
        };
        if out.canonical_bytes()? != raw {
            return Err(corrupt("noncanonical birth declaration"));
        }
        Ok(out)
    }

    pub fn definitions(&self) -> Vec<PeriodDef> {
        self.periods
            .iter()
            .map(|(definition, _)| definition.clone())
            .collect()
    }
}

fn corrupt(message: impl Into<String>) -> KernelError {
    KernelError::Corrupt(format!("period creation: {}", message.into()))
}

/// One creation identity per book, calendar and fiscal year. The first
/// admitted creator remains attributable; another authorized retry returns
/// that original declaration instead of fabricating a second creation.
pub fn creation_vid(book: &BookContext, fiscal_year: i32) -> VId {
    let digest = domain_digest(
        b"fa:vid:period-creation:v1",
        &[
            &book.book_id.0,
            book.calendar.id.as_bytes(),
            &fiscal_year.to_le_bytes(),
        ],
    );
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

/// Decode and authenticate a creation control against its book's immutable
/// calendar and birth law. Used by retry, chart/REA readers, and verification.
/// The caller selects a row visible at the requested prefix; a raw row may
/// retain a retirement later than that prefix, which is not evidence against
/// what was true at the earlier coordinate.
pub fn declared_creation(
    row: &VertexRow,
    book: &BookContext,
    spec: &BookSpec,
) -> Result<PeriodCreation, KernelError> {
    let entry = Entry::decode(&bytes(
        row,
        property::FA_PAYLOAD,
        "period creation payload",
    )?)?;
    let payload = &entry.proposal;
    let Some(ControlPayload::SchemaChange {
        kind: SCHEMA_CHANGE_CREATE_PERIODS,
        canonical_bytes,
    }) = &payload.control
    else {
        return Err(corrupt("control does not carry CreatePeriods"));
    };
    let creation = PeriodCreation::decode(canonical_bytes)?;
    let body_digest = domain_digest(DOMAIN, &[canonical_bytes]);
    if payload.class != EntryClass::SCHEMA_CONTROL
        || payload.book_id != book.book_id
        || payload.branch_id != Id128::TRUNK
        || payload.effective_date != DateDay(0)
        || payload.effective_period.is_some()
        || payload.document_date.is_some()
        || payload.session_ref.is_some()
        || payload.idempotency_key != creation.fiscal_year.to_le_bytes()
        || !matches!(payload.origin, EntryOrigin::Control {
            control_kind: ControlKind::PERIOD_CREATION, spec_body_digest,
        } if spec_body_digest == body_digest)
        || row.vid != creation_vid(book, creation.fiscal_year)
        || row.labels.as_slice() != [label::ENTRY]
        || creation != PeriodCreation::from_spec(spec, creation.fiscal_year)?
    {
        return Err(corrupt(
            "control identity, scope or declaration disagrees with the birth law",
        ));
    }
    if row.props != entry_mirrors(&entry)? {
        return Err(corrupt(
            "control mirrors disagree with its canonical payload",
        ));
    }
    Ok(creation)
}

/// Immutable birth definition retained at a recorded coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodBirth {
    pub definition: PeriodDef,
    pub born_state: PeriodState,
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
}

/// Reconstruct all births from retained creation controls at this prefix.
/// Period projections are deliberately not consulted. This reads the visible
/// declarations; it does not prove that an earlier control was never rewritten
/// or retired. Complete journal integrity requires [`crate::verify_entry_history`]
/// with native history loaded through the same prefix.
pub fn births_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    known_at: CommitSeq,
) -> Result<BTreeMap<String, PeriodBirth>, KernelError> {
    let rows = db.vertices_at(known_at)?;
    births_from_rows(&rows, book)
}

pub(crate) fn births_from_rows(
    rows: &[VertexRow],
    book: &BookContext,
) -> Result<BTreeMap<String, PeriodBirth>, KernelError> {
    let root = rows
        .iter()
        .find(|row| row.vid == book_root())
        .ok_or_else(|| corrupt("book root absent at requested prefix"))?;
    let spec = BookSpec::decode(&bytes(root, property::FA_PAYLOAD, "book payload")?)?;
    if spec.book_id != book.book_id || spec.calendar != book.calendar {
        return Err(corrupt("book context disagrees with the immutable genesis"));
    }
    let mut births = BTreeMap::new();
    for row in rows {
        if !row.labels.contains(&label::ENTRY) {
            continue;
        }
        let entry = Entry::decode(&bytes(row, property::FA_PAYLOAD, "entry payload")?)?;
        let relevant = matches!(
            entry.proposal.origin,
            EntryOrigin::Control {
                control_kind: ControlKind::PERIOD_CREATION,
                ..
            }
        ) || matches!(
            entry.proposal.control,
            Some(ControlPayload::SchemaChange {
                kind: SCHEMA_CHANGE_CREATE_PERIODS,
                ..
            })
        );
        if !relevant {
            continue;
        }
        for (definition, born_state) in declared_creation(row, book, &spec)?.periods {
            let code = definition.code.clone();
            let birth = PeriodBirth {
                definition,
                born_state,
                recorded_at: row.created_at,
                control_entry: row.vid,
            };
            if births.insert(code.clone(), birth).is_some() {
                return Err(corrupt(format!(
                    "period `{code}` has multiple creation declarations"
                )));
            }
        }
    }
    Ok(births)
}

/// A legacy Period's first visible native version. `VertexRow.created_at`
/// dates a content version and advances on every state transition; it is
/// not the element's permanent birth. A live, never-recreated Period has
/// monotone presence, so historical point reads recover its original
/// sequence without supplying or synthesizing a recorded timestamp.
fn projection_birth_at<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    vid: VId,
    known_at: CommitSeq,
) -> Result<Option<CommitSeq>, KernelError> {
    if db.vertex_at(vid, known_at)?.is_none() {
        return Ok(None);
    }
    let mut first = 0;
    let mut last = known_at.0;
    while first < last {
        let middle = first + (last - first) / 2;
        if db.vertex_at(vid, CommitSeq(middle))?.is_some() {
            last = middle;
        } else {
            first = middle + 1;
        }
    }
    Ok(Some(CommitSeq(first)))
}

struct PreparedCreation {
    txn: WriteTxn,
    capability: Capability,
    definition: PeriodCreation,
}

enum CreationPreparation {
    Recorded(CommitSeq, Vec<PeriodDef>),
    Ready(Box<PreparedCreation>),
}

fn verify_recorded_projection<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn,
    db: &Database<V>,
    book: &BookContext,
    recorded: &PeriodCreation,
) -> Result<(), KernelError> {
    let verification = crate::period::verify_periods(db, book, None)?;
    if !verification.is_green() {
        return Err(corrupt(format!(
            "recorded birth has projection drift: {}",
            verification.drift.join("; ")
        )));
    }
    for account in list_accounts(db)? {
        if account
            .limit
            .is_some_and(|limit| limit.scope == LimitScope::Period)
        {
            for (period, _) in &recorded.periods {
                let cell = txn.vertex(db, period_cell_vid(account.vid, &period.code))?
                    .ok_or_else(|| corrupt(format!(
                        "recorded birth is missing the limit cell for account `{}` in period `{}`",
                        account.code, period.code
                    )))?;
                if cell.labels.as_slice() != [label::LIMIT_CELL] || cell.retired_at.is_some() {
                    return Err(corrupt(format!(
                        "period `{}` has a retired or mislabeled limit cell",
                        period.code
                    )));
                }
                LimitCell::decode_bound(&cell, account.vid, Some(&period.code))?;
            }
        }
    }
    Ok(())
}

impl PreparedCreation {
    async fn commit<V: asupersync::fs::Vfs + Clone>(
        self,
        db: &mut Database<V>,
        ctx: &PurposeContexts,
    ) -> Outcome<(CommitSeq, Vec<PeriodDef>)> {
        ctx.commit()
            .checkpoint()
            .map_err(WriteTxnError::Interrupted)?;
        let Self {
            mut txn,
            capability,
            definition,
        } = self;
        if let Err(denial) = fa_policy::current(&capability, db.frontier()?) {
            txn.abort();
            return Ok(Err(policy::refusal(&denial)));
        }
        match txn.commit(db, &ctx.commit()).await {
            Ok(sequence) => Ok(Ok((sequence, definition.definitions()))),
            Err(WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins { detail, .. })) => {
                Ok(Err(Refusal::new(
                    code::CONFLICT,
                    exit::CONFLICT,
                    format!("period creation's authority or schema witness changed: {detail}"),
                    "FA-INV-10 / FG-LAW-FCW-01",
                    "retry period creation against the current policy and book",
                )))
            }
            Err(error) => Err(error.into()),
        }
    }
}

/// Create a fiscal year's immutable birth declaration and Period projections
/// under the presented schema capability, in one transaction.
pub async fn create_periods<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fiscal_year: i32,
    principal: VId,
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<(CommitSeq, Vec<PeriodDef>)> {
    match prepare_creation(
        db,
        ctx,
        book,
        fiscal_year,
        principal,
        description,
        capability,
    )? {
        Err(refusal) => Ok(Err(refusal)),
        Ok(CreationPreparation::Recorded(sequence, periods)) => Ok(Ok((sequence, periods))),
        Ok(CreationPreparation::Ready(prepared)) => (*prepared).commit(db, ctx).await,
    }
}

fn prepare_creation<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fiscal_year: i32,
    principal: VId,
    description: Erasable<String>,
    capability: &Capability,
) -> Outcome<CreationPreparation> {
    ctx.txn().checkpoint().map_err(WriteTxnError::Interrupted)?;
    let key = fa_policy::sod::control_key("SchemaControl", None, "CreatePeriods");
    let Some(op) = policy::steward()?.preparer_op(&key) else {
        return Ok(Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED,
            exit::REFUSAL,
            "period creation has no registered authority rule",
            "sod_policy.toml#schema-period-create",
            "install a build with the registered CreatePeriods authority checker",
        )));
    };
    if let Err(denial) = fa_policy::admit_within(
        capability,
        &Intent {
            principal,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
        &Reach::whole_book(true),
        None,
    ) {
        return Ok(Err(policy::refusal(&denial)));
    }
    if let Err(refusal) = policy::current_at(db, book, capability)? {
        return Ok(Err(refusal));
    }
    // A fiscal year the calendar cannot generate (a custom calendar's
    // undeclared year, or a year outside the representable range) is the
    // caller's argument, not a corrupt book.
    if let Err(error) = book.calendar.periods_for_year(fiscal_year) {
        return Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            format!(
                "calendar `{}` has no fiscal year {fiscal_year}: {error}",
                book.calendar.id
            ),
            "plan §7.2 (a fiscal calendar generates the periods of the years it defines)",
            "create a fiscal year the calendar defines; `fa calendar show --json` describes it",
        )));
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(refusal) = policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let epoch = policy::epoch_witness(&txn, db)?;
    let root = txn
        .vertex(db, book_root())?
        .ok_or_else(|| corrupt("no book genesis row"))?;
    let spec_bytes = bytes(&root, property::FA_PAYLOAD, "book payload")?;
    let spec = BookSpec::decode(&spec_bytes)?;
    if spec.book_id != book.book_id || spec.calendar != book.calendar {
        txn.abort();
        return Err(corrupt("book context disagrees with the immutable genesis"));
    }
    let definition = PeriodCreation::from_spec(&spec, fiscal_year)?;
    let canonical_bytes = definition.canonical_bytes()?;
    let body_digest = domain_digest(DOMAIN, &[&canonical_bytes]);
    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEMA_CONTROL,
        // The v1 Entry container requires this scalar; the registered new
        // control reserves zero as an uninterpreted wire placeholder. No
        // effective-day mirror or posting period is created for it.
        effective_date: DateDay(0),
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::SchemaChange {
            kind: SCHEMA_CHANGE_CREATE_PERIODS,
            canonical_bytes,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: fiscal_year.to_le_bytes().to_vec(),
        origin: EntryOrigin::Control {
            control_kind: ControlKind::PERIOD_CREATION,
            spec_body_digest: body_digest,
        },
        principal_ref: principal,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let digest = proposal.proposal_digest()?;
    if let Err(refusal) = policy::authorize_approvals(
        &txn,
        db,
        book,
        &[],
        &digest,
        epoch,
        &key,
        0,
        Party {
            principal,
            profile: capability.profile(),
        },
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let evid = creation_vid(book, fiscal_year);
    if let Some(row) = txn.vertex(db, evid)? {
        let recorded = declared_creation(&row, book, &spec)?;
        // A successful retry must not hide lost or rewritten projections.
        verify_recorded_projection(&txn, db, book, &recorded)?;
        let result = CreationPreparation::Recorded(row.created_at, recorded.definitions());
        txn.abort();
        return Ok(Ok(result));
    }
    // Old books never retained a creator or a birth control. An authorized
    // retry may return their original, validated projection sequence, but
    // must not invent a historical declaration. New years still use the
    // journaled path below.
    if spec_bytes.starts_with(&1_u16.to_le_bytes())
        && let Some((first, _)) = definition.periods.first()
        && let Some(row) = txn.vertex(db, fa_model::period_vid(&book.calendar.id, &first.code))?
    {
        let cutover = births_at(db, book, db.frontier()?)?
            .values()
            .map(|birth| birth.recorded_at)
            .min();
        let first_sequence = projection_birth_at(db, row.vid, db.frontier()?)?
            .ok_or_else(|| corrupt("legacy period lost its native birth"))?;
        if cutover.is_none_or(|sequence| first_sequence < sequence) {
            for (period, _) in &definition.periods {
                let projected = txn
                    .vertex(db, fa_model::period_vid(&book.calendar.id, &period.code))?
                    .ok_or_else(|| {
                        corrupt(format!(
                            "legacy fiscal year is missing period `{}`",
                            period.code
                        ))
                    })?;
                if projection_birth_at(db, projected.vid, db.frontier()?)? != Some(first_sequence) {
                    return Err(corrupt("legacy fiscal year was not created atomically"));
                }
            }
            verify_recorded_projection(&txn, db, book, &definition)?;
            txn.abort();
            return Ok(Ok(CreationPreparation::Recorded(
                first_sequence,
                definition.definitions(),
            )));
        }
    }
    let entry = proposal.seal(Vec::new(), None)?;
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    batch.add_edge(
        edge_id(relation::IN_BOOK, evid, book_root()),
        evid,
        book_root(),
        vec![],
    );
    for (period, state) in &definition.periods {
        let pvid = fa_model::period_vid(&book.calendar.id, &period.code);
        if txn.vertex(db, pvid)?.is_some() {
            txn.abort();
            return Err(corrupt(format!(
                "period `{}` already exists without its birth declaration",
                period.code
            )));
        }
        let mut props = vec![
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (
                property::CALENDAR_ID,
                scalar_text("calendar_id", &book.calendar.id)?,
            ),
            (property::CODE, scalar_text("code", &period.code)?),
            (
                property::FISCAL_YEAR,
                CanonicalScalar::Int(i64::from(period.fiscal_year)),
            ),
            (
                property::ORDINAL,
                CanonicalScalar::Int(i64::from(period.ordinal)),
            ),
            (
                property::PERIOD_KIND,
                CanonicalScalar::Int(kind_tag(period.kind)),
            ),
            (
                property::PERIOD_START,
                CanonicalScalar::Int(i64::from(period.start.0)),
            ),
            (
                property::PERIOD_END,
                CanonicalScalar::Int(i64::from(period.end.0)),
            ),
            (
                property::STATE,
                CanonicalScalar::Int(i64::from(state.tag())),
            ),
        ];
        props.sort_by_key(|(key, _)| key.0);
        batch.create_vertex(pvid, vec![label::PERIOD], props);
        batch.add_edge(
            edge_id(relation::IN_BOOK, pvid, book_root()),
            pvid,
            book_root(),
            vec![],
        );
    }
    for account in list_accounts(db)? {
        if account
            .limit
            .is_some_and(|limit| limit.scope == LimitScope::Period)
        {
            let _ = txn.vertex(db, account.vid)?;
            for (period, _) in &definition.periods {
                batch.create_vertex(
                    period_cell_vid(account.vid, &period.code),
                    vec![label::LIMIT_CELL],
                    LimitCell::default().create_props(account.vid, Some(&period.code))?,
                );
            }
        }
    }
    txn.write_ordered(db, vec![batch])?;
    Ok(Ok(CreationPreparation::Ready(Box::new(PreparedCreation {
        txn,
        capability: capability.clone(),
        definition,
    }))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use asupersync::runtime::{Runtime, RuntimeBuilder};
    use asupersync::{Budget, Cx};
    use fa_model::{SealKey, SymbolTable, account_vid, period_vid};
    use fa_money::UnitRegistry;
    use fa_policy::{Op, Profile};
    use fa_time::FiscalCalendar;
    use fgdb::{DatabaseKeys, MemVfs};
    use fgdb_types::ids::DatabaseSecurityNamespaceId;

    const PRINCIPAL: VId = VId(7);

    struct Harness {
        runtime: Runtime,
        root: Cx,
        db: Database<MemVfs>,
        book: BookContext,
    }

    impl Harness {
        fn new() -> Self {
            let runtime = RuntimeBuilder::new().build().unwrap();
            let root = runtime.request_cx_with_budget(Budget::INFINITE);
            let ctx = PurposeContexts::narrow_runtime_root(&root);
            let keys = DatabaseKeys::new(
                [0x71; 32],
                DatabaseSecurityNamespaceId([0x72; 32]),
                [0x73; 32],
            );
            let mut db = runtime
                .block_on(Database::open_memory(&ctx.commit(), keys))
                .unwrap();
            let units = UnitRegistry::with_defaults();
            let calendar = FiscalCalendar::monthly("cal", 1, 1).unwrap();
            let symbols = SymbolTable::compiled();
            let spec = BookSpec {
                book_id: Id128([9; 16]),
                name: "Period births".into(),
                base_unit: units.lookup("USD").unwrap(),
                calendar: calendar.clone(),
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            };
            runtime
                .block_on(crate::genesis::create_book(
                    &mut db, &ctx, &spec, &units, &symbols,
                ))
                .unwrap();
            Self {
                runtime,
                root,
                db,
                book: BookContext {
                    book_id: spec.book_id,
                    calendar,
                    units,
                    seal_key: SealKey([0x74; 32]),
                    symbols,
                },
            }
        }

        fn ctx(&self) -> PurposeContexts {
            PurposeContexts::narrow_runtime_root(&self.root)
        }

        fn description(&self, nonce: u8) -> Erasable<String> {
            Erasable::seal(
                &"create fiscal periods".into(),
                None,
                &self.book.seal_key,
                [nonce; 32],
                [nonce; 24],
            )
        }

        fn create_with(
            &mut self,
            year: i32,
            principal: VId,
            capability: &Capability,
            nonce: u8,
        ) -> Outcome<(CommitSeq, Vec<PeriodDef>)> {
            let ctx = self.ctx();
            let description = self.description(nonce);
            self.runtime.block_on(create_periods(
                &mut self.db,
                &ctx,
                &self.book,
                year,
                principal,
                description,
                capability,
            ))
        }

        fn create(&mut self, year: i32) -> (CommitSeq, Vec<PeriodDef>) {
            self.create_with(year, PRINCIPAL, &schema(), 1)
                .unwrap()
                .unwrap()
        }

        fn prepare(&mut self, year: i32, capability: &Capability) -> PreparedCreation {
            let ctx = self.ctx();
            let description = self.description(2);
            match prepare_creation(
                &mut self.db,
                &ctx,
                &self.book,
                year,
                PRINCIPAL,
                description,
                capability,
            )
            .unwrap()
            .unwrap()
            {
                CreationPreparation::Ready(prepared) => *prepared,
                CreationPreparation::Recorded(..) => panic!("fresh year already recorded"),
            }
        }

        fn commit(&mut self, prepared: PreparedCreation) -> Outcome<(CommitSeq, Vec<PeriodDef>)> {
            let ctx = self.ctx();
            self.runtime.block_on(prepared.commit(&mut self.db, &ctx))
        }

        fn write_raw(&mut self, batch: WriteBatch) -> CommitSeq {
            let ctx = self.ctx();
            self.runtime
                .block_on(self.db.write(&ctx.commit(), batch))
                .unwrap()
        }

        fn limited_account(&mut self) -> VId {
            let usd = self.book.units.lookup("USD").unwrap();
            let account = crate::genesis::AccountSpec {
                code: "1000".into(),
                name: "Cash".into(),
                account_type: 1,
                normal_balance: 0,
                is_leaf: true,
                unit_policy: crate::genesis::UnitPolicy::Single(usd),
                parent_code: None,
                limit: Some(crate::limit::BalanceLimit {
                    lower: Some(0),
                    upper: None,
                    scope: LimitScope::Period,
                }),
            };
            let ctx = self.ctx();
            let description = self.description(3);
            self.runtime
                .block_on(crate::genesis::install_chart(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    &[account],
                    PRINCIPAL,
                    DateDay::from_ymd(2026, 1, 1).unwrap(),
                    b"period-test-chart",
                    description,
                    &schema(),
                ))
                .unwrap()
                .unwrap();
            account_vid(self.book.book_id, "1000")
        }

        fn revoke(&mut self, capability: &Capability) {
            let ctx = self.ctx();
            let request = policy::RevocationRequest {
                capability: Capability::embedded(VId(21), &["issue_capability"]).unwrap(),
                revoked: capability.commitment().unwrap(),
                effective_date: DateDay::from_ymd(2026, 1, 1).unwrap(),
                idempotency_key: b"revoke-schema".to_vec(),
                description: self.description(4),
            };
            self.runtime
                .block_on(policy::revoke_capability(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    request,
                ))
                .unwrap()
                .unwrap();
        }

        fn activate_policy(&mut self) {
            let ctx = self.ctx();
            let proposal = policy::activation_proposal(
                &self.book,
                PRINCIPAL,
                policy::steward().unwrap().policy_oid,
                DateDay::from_ymd(2026, 1, 1).unwrap(),
                b"period-policy",
                self.description(5),
            );
            let digest = proposal.proposal_digest().unwrap();
            let mut approvals = Vec::new();
            for principal in [VId(21), VId(22)] {
                let request = policy::ApprovalRequest {
                    capability: Capability::embedded(principal, &["approve"]).unwrap(),
                    approved_proposal_digest: digest,
                    role: 0,
                };
                approvals.push(
                    self.runtime
                        .block_on(policy::record_approval(
                            &mut self.db,
                            &ctx,
                            &self.book,
                            request,
                        ))
                        .unwrap()
                        .unwrap()
                        .approval(),
                );
            }
            let request = policy::ActivationRequest {
                proposal,
                approvals,
                capability: Capability::embedded(PRINCIPAL, &["rule_change"]).unwrap(),
            };
            self.runtime
                .block_on(policy::activate_policy(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    request,
                ))
                .unwrap()
                .unwrap();
        }

        fn open(&mut self, period: &PeriodDef) -> CommitSeq {
            let ctx = self.ctx();
            let description = self.description(6);
            let transitioned = self
                .runtime
                .block_on(crate::period::transition_period(
                    &mut self.db,
                    &ctx,
                    &self.book,
                    &period.code,
                    fa_time::PeriodTransition::Open,
                    PRINCIPAL,
                    1,
                    period.code.as_bytes(),
                    description,
                    &Capability::embedded(PRINCIPAL, &["close"]).unwrap(),
                    &[],
                ))
                .unwrap()
                .unwrap();
            transitioned.recorded_at
        }

        /// A version-1 wire fixture: its immutable Periods were written by
        /// the old projection-only format, which had no creator record.
        fn legacy_year(&mut self, year: i32) -> (CommitSeq, Vec<PeriodDef>) {
            let result = self.create(year);
            let root = self.db.vertex(book_root()).unwrap().unwrap();
            let mut payload = bytes(&root, property::FA_PAYLOAD, "book").unwrap();
            payload[..2].copy_from_slice(&1_u16.to_le_bytes());
            assert!(BookSpec::decode(&payload).is_ok());
            let control = creation_vid(&self.book, year);
            let mut fixture = WriteBatch::new(relation::IN_BOOK);
            fixture.set_vertex_property(
                book_root(),
                property::FA_PAYLOAD,
                Some(scalar_bytes("book", payload).unwrap()),
            );
            fixture.delete_edge(edge_id(relation::IN_BOOK, control, book_root()));
            fixture.delete_vertex(control);
            self.write_raw(fixture);
            result
        }
    }

    fn schema() -> Capability {
        Capability::embedded(PRINCIPAL, &["schema_change"]).unwrap()
    }

    #[test]
    fn birth_codec_covers_historical_law_and_the_largest_registered_calendar() {
        let units = UnitRegistry::with_defaults();
        let mut spec = BookSpec {
            book_id: Id128([9; 16]),
            name: "Birth codec".into(),
            base_unit: units.lookup("USD").unwrap(),
            calendar: FiscalCalendar::monthly("cal", 1, 1).unwrap(),
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: Some(DateDay::from_ymd(2026, 7, 1).unwrap()),
        };
        let historic = PeriodCreation::from_spec(&spec, 2026).unwrap();
        assert_eq!(
            historic
                .periods
                .iter()
                .filter(|(period, state)| {
                    period.kind == PeriodKind::Historical && *state == PeriodState::Locked
                })
                .count(),
            6
        );
        assert!(historic.periods.iter().any(|(period, state)| {
            period.kind == PeriodKind::Opening && *state == PeriodState::Locked
        }));
        assert_eq!(
            PeriodCreation::decode(&historic.canonical_bytes().unwrap()).unwrap(),
            historic
        );
        spec.calendar = FiscalCalendar {
            id: "weekly".into(),
            kind: fa_time::CalendarKind::Week5253 {
                end_rule: fa_time::YearEndRule::WeekdayNearestEnd {
                    weekday: fa_time::Weekday::Saturday,
                    month: 12,
                },
            },
            adjustment_periods: fa_time::calendar::MAX_ADJUSTMENT_PERIODS,
        };
        spec.opening_date = None;
        let maximum = PeriodCreation::from_spec(&spec, 2026).unwrap();
        assert_eq!(maximum.periods.len(), 19);
        let bytes = maximum.canonical_bytes().unwrap();
        assert_eq!(PeriodCreation::decode(&bytes).unwrap(), maximum);
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(PeriodCreation::decode(&trailing).is_err());
        let mut transitioned_at_birth = bytes;
        *transitioned_at_birth.last_mut().unwrap() = PeriodState::Open.tag();
        assert!(PeriodCreation::decode(&transitioned_at_birth).is_err());
        let mut version_one = spec.canonical_bytes().unwrap();
        assert!(version_one.starts_with(&2_u16.to_le_bytes()));
        version_one[..2].copy_from_slice(&1_u16.to_le_bytes());
        assert_eq!(BookSpec::decode(&version_one).unwrap(), spec);
        version_one[..2].copy_from_slice(&3_u16.to_le_bytes());
        assert!(BookSpec::decode(&version_one).is_err());
    }

    #[test]
    fn creation_is_atomic_undated_attributable_and_retry_is_the_original_outcome() {
        let mut h = Harness::new();
        let account = h.limited_account();
        let before = h.db.frontier().unwrap();
        assert!(births_at(&h.db, &h.book, before).unwrap().is_empty());
        let (sequence, periods) = h.create(2026);
        assert_eq!(sequence.0, before.0 + 1);
        assert_eq!(periods.len(), 15);
        let control = h.db.vertex(creation_vid(&h.book, 2026)).unwrap().unwrap();
        let entry =
            Entry::decode(&bytes(&control, property::FA_PAYLOAD, "control").unwrap()).unwrap();
        assert_eq!(entry.proposal.principal_ref, PRINCIPAL);
        assert_eq!(entry.proposal.class, EntryClass::SCHEMA_CONTROL);
        assert!(entry.proposal.effective_period.is_none());
        assert!(entry.proposal.legs.is_empty());
        assert!(crate::rows::prop(&control, property::FA_EFFECTIVE_DAY).is_none());
        let births = births_at(&h.db, &h.book, sequence).unwrap();
        assert_eq!(births.len(), periods.len());
        for period in &periods {
            let birth = &births[&period.code];
            assert_eq!(birth.definition, *period);
            assert_eq!(birth.recorded_at, sequence);
            assert_eq!(birth.control_entry, control.vid);
            assert_eq!(
                h.db.vertex(period_vid(&h.book.calendar.id, &period.code))
                    .unwrap()
                    .unwrap()
                    .created_at,
                sequence
            );
            assert_eq!(
                h.db.vertex(period_cell_vid(account, &period.code))
                    .unwrap()
                    .unwrap()
                    .created_at,
                sequence
            );
        }
        // State transitions create native content-version successors. They
        // preserve the original fiscal-year birth and exact retry outcome.
        let opened_at = h.open(&periods[0]);
        let caller = VId(8);
        let retried = h
            .create_with(
                2026,
                caller,
                &Capability::embedded(caller, &["schema_change"]).unwrap(),
                9,
            )
            .unwrap()
            .unwrap();
        assert_eq!(retried, (sequence, periods));
        assert_eq!(h.db.frontier().unwrap(), opened_at);
        let verified = crate::period::verify_periods(&h.db, &h.book, None).unwrap();
        assert!(verified.is_green(), "{:?}", verified.drift);
        assert_eq!(verified.legacy_periods, 0);
        assert_eq!(verified.transitions_checked, 1);
    }

    #[test]
    fn capability_refusals_precede_even_corrupt_genesis_observation() {
        let mut h = Harness::new();
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        damage.set_vertex_property(
            book_root(),
            property::FA_PAYLOAD,
            Some(scalar_bytes("corrupt", vec![0]).unwrap()),
        );
        h.write_raw(damage);
        let head = h.db.frontier().unwrap();
        let cases = [
            (
                "missing operation",
                Capability::embedded(PRINCIPAL, &["read"]).unwrap(),
                "FA-REF-011",
            ),
            (
                "another holder",
                Capability::embedded(VId(8), &["schema_change"]).unwrap(),
                "FA-REF-011",
            ),
            (
                "another book",
                schema().for_books(&[Id128([8; 16])]).unwrap(),
                "FA-REF-011",
            ),
            (
                "account scope",
                schema().for_accounts(&["1000"]).unwrap(),
                "FA-REF-011",
            ),
            (
                "period scope",
                schema().for_periods(&["FY2026-P01"]).unwrap(),
                "FA-REF-011",
            ),
            (
                "agent trunk",
                Capability::new(PRINCIPAL, Profile::Agent, &[Op::Post], VId(21)).unwrap(),
                "FA-REF-013",
            ),
            ("expired", schema().expiring_at(CommitSeq(0)), "FA-REF-014"),
        ];
        for (case, capability, expected) in cases {
            let refusal = h
                .create_with(2026, PRINCIPAL, &capability, 1)
                .expect("authorization must not read the corrupt genesis")
                .unwrap_err();
            assert_eq!(refusal.code, expected, "{case}: {refusal:?}");
            assert_eq!(h.db.frontier().unwrap(), head, "{case}");
        }
    }

    #[test]
    fn revocation_between_prepare_and_commit_conflicts_and_fresh_revoked_requests_refuse() {
        let mut h = Harness::new();
        let capability = schema();
        let prepared = h.prepare(2026, &capability);
        h.revoke(&capability);
        let head = h.db.frontier().unwrap();
        let refusal = h.commit(prepared).unwrap().unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::CONFLICT, exit::CONFLICT)
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(births_at(&h.db, &h.book, head).unwrap().is_empty());
        let refusal = h
            .create_with(2026, PRINCIPAL, &capability, 1)
            .unwrap()
            .unwrap_err();
        assert_eq!(refusal.code, "FA-REF-023");
        assert_eq!(h.db.frontier().unwrap(), head);
    }

    #[test]
    fn policy_activation_invalidates_preparation_and_retry_uses_current_epoch() {
        let mut h = Harness::new();
        let prepared = h.prepare(2026, &schema());
        h.activate_policy();
        let head = h.db.frontier().unwrap();
        let refusal = h.commit(prepared).unwrap().unwrap_err();
        assert_eq!(
            (refusal.code, refusal.exit),
            (code::CONFLICT, exit::CONFLICT)
        );
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(births_at(&h.db, &h.book, head).unwrap().is_empty());
        assert_eq!(policy::security_policy_epoch(&h.db).unwrap(), 1);
        assert_eq!(h.create(2026).0.0, head.0 + 1);
    }

    #[test]
    fn expiry_is_rechecked_immediately_before_publication() {
        let mut h = Harness::new();
        let expiry = CommitSeq(h.db.frontier().unwrap().0 + 1);
        let capability = schema().expiring_at(expiry);
        let prepared = h.prepare(2026, &capability);
        h.activate_policy();
        let head = h.db.frontier().unwrap();
        let refusal = h.commit(prepared).unwrap().unwrap_err();
        assert_eq!(refusal.code, "FA-REF-014");
        assert_eq!(h.db.frontier().unwrap(), head);
        assert!(births_at(&h.db, &h.book, head).unwrap().is_empty());
    }

    #[test]
    fn retry_detects_missing_or_rebound_limit_cells_and_never_repairs_them() {
        for planted in ["missing", "wrong-period"] {
            let mut h = Harness::new();
            let account = h.limited_account();
            let (_, periods) = h.create(2026);
            let cell = period_cell_vid(account, &periods[0].code);
            let mut damage = WriteBatch::new(relation::IN_BOOK);
            if planted == "missing" {
                damage.delete_vertex(cell);
            } else {
                damage.set_vertex_property(
                    cell,
                    property::EFFECTIVE_PERIOD,
                    Some(scalar_text("period", "FY2025-P01").unwrap()),
                );
            }
            let head = h.write_raw(damage);
            assert!(
                matches!(
                    h.create_with(2026, PRINCIPAL, &schema(), 2),
                    Err(KernelError::Corrupt(_))
                ),
                "{planted}"
            );
            assert_eq!(h.db.frontier().unwrap(), head);
        }
    }

    #[test]
    fn journal_births_detect_entire_missing_year_and_control_loss_at_the_selected_prefix() {
        for planted in ["all-periods", "birth-control", "interval"] {
            let mut h = Harness::new();
            let (clean, periods) = h.create(2026);
            let mut damage = WriteBatch::new(relation::IN_BOOK);
            match planted {
                "all-periods" => {
                    for period in &periods {
                        let vid = period_vid(&h.book.calendar.id, &period.code);
                        damage.delete_edge(edge_id(relation::IN_BOOK, vid, book_root()));
                        damage.delete_vertex(vid);
                    }
                }
                "birth-control" => {
                    let vid = creation_vid(&h.book, 2026);
                    damage.delete_edge(edge_id(relation::IN_BOOK, vid, book_root()));
                    damage.delete_vertex(vid);
                }
                _ => {
                    damage.set_vertex_property(
                        period_vid(&h.book.calendar.id, &periods[0].code),
                        property::PERIOD_START,
                        Some(CanonicalScalar::Int(0)),
                    );
                }
            }
            let head = h.write_raw(damage);
            let verification = crate::period::verify_periods(&h.db, &h.book, None).unwrap();
            assert!(
                !verification.is_green(),
                "{planted}: {:?}",
                verification.drift
            );
            assert!(
                crate::period::verify_periods(&h.db, &h.book, Some(clean))
                    .unwrap()
                    .is_green()
            );
            assert!(h.create_with(2026, PRINCIPAL, &schema(), 2).is_err());
            assert_eq!(h.db.frontier().unwrap(), head);
            if planted == "all-periods" {
                assert_eq!(
                    births_at(&h.db, &h.book, head).unwrap().len(),
                    periods.len()
                );
            }
        }
    }

    #[test]
    fn v1_baseline_remains_readable_and_new_years_have_independent_birth_provenance() {
        let mut h = Harness::new();
        let legacy = h.legacy_year(2026);
        let old_head = h.db.frontier().unwrap();
        assert!(births_at(&h.db, &h.book, old_head).unwrap().is_empty());
        let old = crate::period::verify_periods(&h.db, &h.book, None).unwrap();
        assert!(old.is_green(), "{:?}", old.drift);
        assert_eq!(old.legacy_periods, legacy.1.len());
        assert_eq!(h.create(2026), legacy);
        assert_eq!(h.db.frontier().unwrap(), old_head);
        let (new_sequence, new_periods) = h.create(2027);
        let transitioned = h.open(&legacy.1[0]);
        let mixed = crate::period::verify_periods(&h.db, &h.book, None).unwrap();
        assert!(mixed.is_green(), "{:?}", mixed.drift);
        assert_eq!(mixed.legacy_periods, legacy.1.len());
        assert_eq!(h.create(2026), legacy);
        assert_eq!(h.db.frontier().unwrap(), transitioned);
        let births = births_at(&h.db, &h.book, new_sequence).unwrap();
        assert_eq!(births.len(), new_periods.len());
        assert!(
            births
                .values()
                .all(|birth| birth.definition.fiscal_year == 2027)
        );
        let mut damage = WriteBatch::new(relation::IN_BOOK);
        for period in &new_periods {
            let vid = period_vid(&h.book.calendar.id, &period.code);
            damage.delete_edge(edge_id(relation::IN_BOOK, vid, book_root()));
            damage.delete_vertex(vid);
        }
        h.write_raw(damage);
        let damaged = crate::period::verify_periods(&h.db, &h.book, None).unwrap();
        assert!(!damaged.is_green());
        assert!(damaged.drift.iter().any(|message| message.contains("2027")));
        assert!(
            crate::period::verify_periods(&h.db, &h.book, Some(old_head))
                .unwrap()
                .is_green()
        );
    }
}
