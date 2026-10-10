//! Book genesis: the book vertex, its units, its periods, and the chart —
//! the last two as journaled schema effects (plan §4.3, §7.3, §8.4).

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128,
    Reader, SealKey, SymbolTable, Writer, account_vid, entry_mirrors, entry_vid, period_vid,
    unit_vid,
};
use fa_money::{UnitId, UnitRegistry};
use fa_time::{
    CalendarKind, DateDay, FiscalCalendar, PeriodDef, PeriodState, WeekPattern, Weekday,
    YearEndRule,
};
use fgdb::{Database, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::limit::{BalanceLimit, LimitCell, LimitScope, limit_cell_vid, period_cell_vid};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, kind_tag, scalar_bytes, scalar_text};

/// What the kernel knows about an open book; the facade holds it.
#[derive(Clone, Debug)]
pub struct BookContext {
    pub book_id: Id128,
    pub calendar: FiscalCalendar,
    pub units: UnitRegistry,
    /// The book key erasable fields without a subject are sealed under.
    pub seal_key: SealKey,
    pub symbols: SymbolTable,
}

/// Genesis parameters; journaled canonically on the book's root vertex so a
/// reopened store rebuilds its context from the journal alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookSpec {
    pub book_id: Id128,
    pub name: String,
    pub base_unit: UnitId,
    pub calendar: FiscalCalendar,
}

const MAX_BOOK_NAME_BYTES: usize = 256;
const MAX_CALENDAR_ID_BYTES: usize = 64;

fn weekday_tag(w: Weekday) -> u8 {
    match w {
        Weekday::Monday => 0,
        Weekday::Tuesday => 1,
        Weekday::Wednesday => 2,
        Weekday::Thursday => 3,
        Weekday::Friday => 4,
        Weekday::Saturday => 5,
        Weekday::Sunday => 6,
    }
}

fn weekday_from_tag(t: u8) -> Option<Weekday> {
    Some(match t {
        0 => Weekday::Monday,
        1 => Weekday::Tuesday,
        2 => Weekday::Wednesday,
        3 => Weekday::Thursday,
        4 => Weekday::Friday,
        5 => Weekday::Saturday,
        6 => Weekday::Sunday,
        _ => return None,
    })
}

fn encode_rule(w: &mut Writer, r: &YearEndRule) {
    match r {
        YearEndRule::LastWeekdayOfMonth { weekday, month } => {
            w.u8(0).u8(weekday_tag(*weekday)).u8(*month);
        }
        YearEndRule::WeekdayNearestEnd { weekday, month } => {
            w.u8(1).u8(weekday_tag(*weekday)).u8(*month);
        }
    }
}

fn decode_rule(r: &mut Reader<'_>) -> Result<YearEndRule, DecodeError> {
    let tag = r.u8("calendar.rule")?;
    let weekday = {
        let t = r.u8("calendar.weekday")?;
        weekday_from_tag(t).ok_or_else(|| r.bad_tag("calendar.weekday", t))?
    };
    let month = r.u8("calendar.month")?;
    Ok(match tag {
        0 => YearEndRule::LastWeekdayOfMonth { weekday, month },
        1 => YearEndRule::WeekdayNearestEnd { weekday, month },
        t => return Err(r.bad_tag("calendar.rule", t)),
    })
}

impl BookSpec {
    /// The canonical `fa:book:v1` bytes journaled on the root vertex.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(1)
            .fixed(&self.book_id.0)
            .str(&self.name)
            .u32(self.base_unit.0)
            .str(&self.calendar.id)
            .u8(self.calendar.adjustment_periods);
        match &self.calendar.kind {
            CalendarKind::Monthly12 { year_start_month } => {
                w.u8(0).u8(*year_start_month);
            }
            CalendarKind::Weeks { pattern, end_rule } => {
                w.u8(1).u8(match pattern {
                    WeekPattern::W445 => 0,
                    WeekPattern::W454 => 1,
                    WeekPattern::W544 => 2,
                });
                encode_rule(&mut w, end_rule);
            }
            CalendarKind::Week5253 { end_rule } => {
                w.u8(2);
                encode_rule(&mut w, end_rule);
            }
        }
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let spec = (|| -> Result<Self, DecodeError> {
            let v = r.u16("book.version")?;
            if v != 1 {
                return Err(r.invalid("book.version"));
            }
            let book_id = Id128(r.fixed("book.id")?);
            let name = r.str(MAX_BOOK_NAME_BYTES, "book.name")?.to_string();
            let base_unit = UnitId(r.u32("book.base_unit")?);
            let id = r.str(MAX_CALENDAR_ID_BYTES, "calendar.id")?.to_string();
            let adjustment_periods = r.u8("calendar.adjustment_periods")?;
            let kind = match r.u8("calendar.kind")? {
                0 => CalendarKind::Monthly12 {
                    year_start_month: r.u8("calendar.year_start_month")?,
                },
                1 => {
                    let p = r.u8("calendar.pattern")?;
                    let pattern = match p {
                        0 => WeekPattern::W445,
                        1 => WeekPattern::W454,
                        2 => WeekPattern::W544,
                        t => return Err(r.bad_tag("calendar.pattern", t)),
                    };
                    CalendarKind::Weeks {
                        pattern,
                        end_rule: decode_rule(&mut r)?,
                    }
                }
                2 => CalendarKind::Week5253 {
                    end_rule: decode_rule(&mut r)?,
                },
                t => return Err(r.bad_tag("calendar.kind", t)),
            };
            r.finish()?;
            Ok(Self {
                book_id,
                name,
                base_unit,
                calendar: FiscalCalendar {
                    id,
                    kind,
                    adjustment_periods,
                },
            })
        })()
        .map_err(|e| KernelError::Model(e.into()))?;
        Ok(spec)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnitPolicy {
    Single(UnitId),
    AnyCurrency,
    AnyUnit,
}

impl UnitPolicy {
    pub(crate) fn mirror(self) -> i64 {
        match self {
            Self::Single(u) => i64::from(u.0),
            Self::AnyCurrency => -1,
            Self::AnyUnit => -2,
        }
    }

    pub(crate) fn from_mirror(v: i64) -> Option<Self> {
        match v {
            -1 => Some(Self::AnyCurrency),
            -2 => Some(Self::AnyUnit),
            v => u32::try_from(v).ok().map(|u| Self::Single(UnitId(u))),
        }
    }
}

/// One account of a chart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountSpec {
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub normal_balance: u8,
    pub is_leaf: bool,
    pub unit_policy: UnitPolicy,
    pub parent_code: Option<String>,
    /// A balance limit in the account's single unit and normal-balance sign
    /// (plan §5.4–5.5); the account then owns a `LimitCell`.
    pub limit: Option<BalanceLimit>,
}

impl AccountSpec {
    fn canonical(&self, w: &mut Writer) {
        w.str(&self.code)
            .str(&self.name)
            .u8(self.account_type)
            .u8(self.normal_balance)
            .bool(self.is_leaf)
            .i64(self.unit_policy.mirror())
            .opt(self.parent_code.as_ref(), |w, p| {
                w.str(p);
            });
    }
}

/// Create the root book vertex (with the canonical spec as its payload) and
/// one `Unit` vertex per registered unit.
pub async fn create_book<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    spec: &BookSpec,
    units: &UnitRegistry,
    symbols: &SymbolTable,
) -> Result<CommitSeq, KernelError> {
    let bvid = book_root();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", spec.canonical_bytes()?)?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", spec.book_id.0.to_vec())?,
        ),
        (property::NAME, scalar_text("name", &spec.name)?),
        (
            property::BASE_UNIT,
            CanonicalScalar::Int(i64::from(spec.base_unit.0)),
        ),
        (
            property::CALENDAR_ID,
            scalar_text("calendar_id", &spec.calendar.id)?,
        ),
        (
            property::SYMBOLS_DIGEST,
            scalar_bytes("symbols_digest", symbols.digest().0.to_vec())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(bvid, vec![label::BOOK], props);
    for (id, unit) in units.iter() {
        let uvid = unit_vid(spec.book_id, &format!("{}@v{}", unit.code, unit.version));
        let mut props = vec![
            (
                property::BOOK_ID,
                scalar_bytes("book_id", spec.book_id.0.to_vec())?,
            ),
            (property::CODE, scalar_text("code", &unit.code)?),
            (property::SCALE, CanonicalScalar::Int(i64::from(unit.scale))),
            (
                property::VERSION,
                CanonicalScalar::Int(i64::from(unit.version)),
            ),
            (property::UNIT_ID, CanonicalScalar::Int(i64::from(id.0))),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(uvid, vec![label::UNIT], props);
        batch.add_edge(edge_id(relation::IN_BOOK, uvid, bvid), uvid, bvid, vec![]);
    }
    Ok(db.write(&ctx.commit(), batch).await?)
}

/// The spec journaled at genesis, or `None` when the store holds no book.
pub fn read_book_spec<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Option<BookSpec>, KernelError> {
    let Some(row) = db.vertex(book_root())? else {
        return Ok(None);
    };
    let payload = bytes(&row, property::FA_PAYLOAD, "book._fa_payload")?;
    BookSpec::decode(&payload).map(Some)
}

/// Create the `Period` vertices of one fiscal year in state `Future`.
/// Opening them is a journaled transition (`period::transition_period`).
pub async fn create_periods<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    fiscal_year: i32,
) -> Result<(CommitSeq, Vec<PeriodDef>), KernelError> {
    let periods = book.calendar.periods_for_year(fiscal_year)?;
    let bvid = book_root();
    let mut batch = WriteBatch::new(relation::IN_BOOK);
    for p in &periods {
        let pvid = period_vid(&book.calendar.id, &p.code);
        let mut props = vec![
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (
                property::CALENDAR_ID,
                scalar_text("calendar_id", &book.calendar.id)?,
            ),
            (property::CODE, scalar_text("code", &p.code)?),
            (
                property::FISCAL_YEAR,
                CanonicalScalar::Int(i64::from(p.fiscal_year)),
            ),
            (
                property::ORDINAL,
                CanonicalScalar::Int(i64::from(p.ordinal)),
            ),
            (
                property::PERIOD_KIND,
                CanonicalScalar::Int(kind_tag(p.kind)),
            ),
            (
                property::PERIOD_START,
                CanonicalScalar::Int(i64::from(p.start.0)),
            ),
            (
                property::PERIOD_END,
                CanonicalScalar::Int(i64::from(p.end.0)),
            ),
            (
                property::STATE,
                CanonicalScalar::Int(i64::from(PeriodState::Future.tag())),
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(pvid, vec![label::PERIOD], props);
        batch.add_edge(edge_id(relation::IN_BOOK, pvid, bvid), pvid, bvid, vec![]);
    }
    // A budget-capped (period-scoped) account owns one limit cell per period,
    // born with the period (plan §5.5), so an absent cell stays corruption.
    for account in list_accounts(db)? {
        if account.limit.is_some_and(|l| l.scope == LimitScope::Period) {
            for p in &periods {
                batch.create_vertex(
                    period_cell_vid(account.vid, &p.code),
                    vec![label::LIMIT_CELL],
                    LimitCell::default().create_props(account.vid, Some(&p.code))?,
                );
            }
        }
    }
    let seq = db.write(&ctx.commit(), batch).await?;
    Ok((seq, periods))
}

/// Every period vertex of the book, in calendar order (fiscal year, ordinal).
pub fn list_periods<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Vec<crate::rows::PeriodRow>, KernelError> {
    let mut out = Vec::new();
    for vid in db.in_neighbours(book_root(), relation::IN_BOOK)? {
        let Some(row) = db.vertex(vid)? else { continue };
        if row.labels.contains(&label::PERIOD) {
            out.push(crate::rows::PeriodRow::decode(&row)?);
        }
    }
    out.sort_by(|a, b| {
        (a.fiscal_year, a.ordinal, a.code.clone()).cmp(&(b.fiscal_year, b.ordinal, b.code.clone()))
    });
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChartInstalled {
    pub recorded_at: CommitSeq,
    pub control_entry: VId,
    pub accounts: usize,
}

/// Install a chart as one journaled schema effect: a `SchemaControl` entry
/// (legs = [], `ControlPayload::SchemaChange` over the canonical chart bytes)
/// plus the `Account` vertices and their `CHILD_OF` edges, in one commit.
#[allow(clippy::too_many_arguments)]
pub async fn install_chart<V: asupersync::fs::Vfs + Clone>(
    db: &mut Database<V>,
    ctx: &PurposeContexts,
    book: &BookContext,
    accounts: &[AccountSpec],
    principal_ref: VId,
    effective_date: DateDay,
    idempotency_key: &[u8],
    description: Erasable<String>,
) -> Outcome<ChartInstalled> {
    // Structural refusals first; nothing is written.
    for a in accounts {
        if a.code.is_empty() || a.code.len() > 64 {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("account code `{}` must be 1..=64 bytes", a.code),
                "Appendix A Account.code",
                "shorten the code",
            )));
        }
        if !fa_model::AccountType(a.account_type).is_registered() {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "account `{}` has unregistered type {}",
                    a.code, a.account_type
                ),
                "registries/account_types.toml",
                "use a registered account type tag (1 Asset … 7 Statistical)",
            )));
        }
        if let Some(p) = &a.parent_code
            && !accounts.iter().any(|x| &x.code == p)
        {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "account `{}` names parent `{p}` which is not in the chart",
                    a.code
                ),
                "plan §4.3 (the chart is a forest)",
                "add the parent account or drop parent_code",
            )));
        }
        if let Some(p) = &a.parent_code
            && accounts.iter().any(|x| &x.code == p && x.is_leaf)
        {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!("account `{}` has leaf `{p}` as its parent", a.code),
                "plan §4.3 (only summaries have children)",
                "mark the parent as a summary",
            )));
        }
        if let Some(limit) = &a.limit {
            let why = if !limit.is_well_formed() {
                Some("a balance limit names at least one bound, with lower ≤ upper")
            } else if !a.is_leaf {
                Some("a balance limit belongs on a leaf (only leaves accept legs)")
            } else if !matches!(a.unit_policy, UnitPolicy::Single(_)) {
                Some("a balance limit is stated in the account's single registered unit")
            } else {
                None
            };
            if let Some(why) = why {
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!("account `{}`: {why}", a.code),
                    "plan §5.4–5.5 (balance limits)",
                    "give the account one unit, make it a leaf, and name lower ≤ upper (or drop the limit)",
                )));
            }
        }
    }
    let mut w = Writer::new();
    w.list(accounts, |w, a| a.canonical(w));
    // Limits are an additive trailing list, written only when the chart
    // declares one, so a chart without limits keeps its canonical bytes.
    let limits: Vec<(&str, BalanceLimit)> = accounts
        .iter()
        .filter_map(|a| a.limit.map(|l| (a.code.as_str(), l)))
        .collect();
    if !limits.is_empty() {
        w.list(&limits, |w, (code, l)| {
            w.str(code)
                .opt(l.lower.as_ref(), |w, v| {
                    w.i128(*v);
                })
                .opt(l.upper.as_ref(), |w, v| {
                    w.i128(*v);
                });
        });
    }
    // Budget caps (period-scoped limits, plan §5.5) are a second trailing
    // list of their account codes, written only when one exists, so every
    // earlier chart (with or without lifetime limits) keeps its bytes.
    let period_scoped: Vec<&str> = limits
        .iter()
        .filter(|(_, l)| l.scope == LimitScope::Period)
        .map(|(code, _)| *code)
        .collect();
    if !period_scoped.is_empty() {
        w.list(&period_scoped, |w, code| {
            w.str(code);
        });
    }
    let canonical_bytes = w.finish().map_err(fa_model::EntryError::from)?;

    let proposal = EntryPayload {
        schema_minor: fa_model::entry::SCHEMA_MINOR,
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        class: EntryClass::SCHEMA_CONTROL,
        effective_date,
        document_date: None,
        description,
        effective_period: None,
        legs: Vec::new(),
        control: Some(ControlPayload::SchemaChange {
            kind: 1,
            canonical_bytes,
        }),
        unit_totals: Vec::new(),
        base_totals: None,
        idempotency_key: idempotency_key.to_vec(),
        origin: EntryOrigin::Control {
            control_kind: 1,
            spec_body_digest: fgdb_crypto::hash(idempotency_key).0,
        },
        principal_ref,
        session_ref: None,
        evidence: Vec::new(),
        supersession: Vec::new(),
        pending: None,
        external_ids: Vec::new(),
        extensions: Vec::new(),
        tags: Vec::new(),
    };
    let entry: Entry = proposal.seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    // A budget-capped account is born with one cell per existing period.
    let existing_periods = if accounts
        .iter()
        .any(|a| a.limit.is_some_and(|l| l.scope == LimitScope::Period))
    {
        list_periods(db)?
    } else {
        Vec::new()
    };
    let mut batch = WriteBatch::new(relation::CHILD_OF);
    batch.create_vertex(evid, vec![label::ENTRY], entry_mirrors(&entry)?);
    for a in accounts {
        let avid = account_vid(book.book_id, &a.code);
        let mut props = vec![
            (
                property::BOOK_ID,
                scalar_bytes("book_id", book.book_id.0.to_vec())?,
            ),
            (property::CODE, scalar_text("code", &a.code)?),
            (property::NAME, scalar_text("name", &a.name)?),
            (
                property::ACCOUNT_TYPE,
                CanonicalScalar::Int(i64::from(a.account_type)),
            ),
            (
                property::NORMAL_BALANCE,
                CanonicalScalar::Int(i64::from(a.normal_balance)),
            ),
            (
                property::POSTING,
                CanonicalScalar::Int(i64::from(a.is_leaf)),
            ),
            (
                property::UNIT_POLICY,
                CanonicalScalar::Int(a.unit_policy.mirror()),
            ),
        ];
        if let Some(limit) = &a.limit {
            props.extend(limit.props()?);
        }
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(avid, vec![label::ACCOUNT], props);
        // A limited account's reservation cell is born with it (plan §5.5
        // interim R-ESC): zero sums, generation 0 — one cell for a lifetime
        // limit, one per existing period for a budget cap (later periods get
        // theirs from `create_periods`).
        match a.limit.map(|l| l.scope) {
            None => {}
            Some(LimitScope::Lifetime) => {
                batch.create_vertex(
                    limit_cell_vid(avid),
                    vec![label::LIMIT_CELL],
                    LimitCell::default().create_props(avid, None)?,
                );
            }
            Some(LimitScope::Period) => {
                for p in &existing_periods {
                    batch.create_vertex(
                        period_cell_vid(avid, &p.code),
                        vec![label::LIMIT_CELL],
                        LimitCell::default().create_props(avid, Some(&p.code))?,
                    );
                }
            }
        }
    }
    for a in accounts {
        if let Some(p) = &a.parent_code {
            let child = account_vid(book.book_id, &a.code);
            let parent = account_vid(book.book_id, p);
            batch.add_edge(
                edge_id(relation::CHILD_OF, child, parent),
                child,
                parent,
                vec![],
            );
        }
    }
    // Every account is IN_BOOK so the chart can be listed from the root; a
    // second relation means a second batch, staged in order in one commit.
    let mut in_book = WriteBatch::new(relation::IN_BOOK);
    let root = book_root();
    for a in accounts {
        let avid = account_vid(book.book_id, &a.code);
        in_book.add_edge(edge_id(relation::IN_BOOK, avid, root), avid, root, vec![]);
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(e) = txn.write_ordered(db, vec![batch, in_book]) {
        txn.abort();
        return Err(e.into());
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ChartInstalled {
            recorded_at: seq,
            control_entry: evid,
            accounts: accounts.len(),
        })),
        Err(fgdb::WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "an account or control entry with this identity already exists",
            "plan §4.9 (identities are derived; a duplicate is a point conflict)",
            "use a fresh idempotency key and omit accounts already installed",
        ))),
        Err(e) => Err(e.into()),
    }
}

/// Every account of the chart, sorted by code.
pub fn list_accounts<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
) -> Result<Vec<crate::rows::AccountRow>, KernelError> {
    let mut out = Vec::new();
    for vid in db.in_neighbours(book_root(), relation::IN_BOOK)? {
        let Some(row) = db.vertex(vid)? else { continue };
        if row.labels.contains(&label::ACCOUNT) {
            out.push(crate::rows::AccountRow::decode(&row)?);
        }
    }
    out.sort_by(|a, b| a.code.cmp(&b.code));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn book_spec_round_trips_every_calendar_kind() {
        let rule = YearEndRule::WeekdayNearestEnd {
            weekday: Weekday::Saturday,
            month: 1,
        };
        for kind in [
            CalendarKind::Monthly12 {
                year_start_month: 7,
            },
            CalendarKind::Weeks {
                pattern: WeekPattern::W454,
                end_rule: YearEndRule::LastWeekdayOfMonth {
                    weekday: Weekday::Sunday,
                    month: 12,
                },
            },
            CalendarKind::Week5253 { end_rule: rule },
        ] {
            let spec = BookSpec {
                book_id: Id128([4; 16]),
                name: "Round Trip Co".into(),
                base_unit: UnitId(3),
                calendar: FiscalCalendar {
                    id: "fy".into(),
                    kind,
                    adjustment_periods: 2,
                },
            };
            let bytes = spec.canonical_bytes().unwrap();
            assert_eq!(BookSpec::decode(&bytes).unwrap(), spec);
            assert!(BookSpec::decode(&bytes[..bytes.len() - 1]).is_err());
        }
    }
}
