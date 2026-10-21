//! Book genesis: the book vertex, its units, its periods, and the chart —
//! the last two as journaled schema effects (plan §4.3, §7.3, §8.4).

use fa_model::symbols::{label, property, relation};
use fa_model::{
    ControlPayload, DecodeError, Entry, EntryClass, EntryOrigin, EntryPayload, Erasable, Id128,
    Reader, SealKey, SymbolTable, Writer, account_vid, entry_mirrors, entry_vid, unit_vid,
};
use fa_money::{UnitId, UnitRegistry};
use fa_time::{
    CalendarKind, DateDay, FiscalCalendar, PeriodDef, PeriodKind, PeriodState, WeekPattern,
    Weekday, YearEndRule,
};
use fgdb::{Database, WriteBatch};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use crate::limit::{BalanceLimit, LimitCell, LimitScope, limit_cell_vid, period_cell_vid};
use crate::refusal::{KernelError, Outcome, Refusal, code, exit};
use crate::rows::{book_root, bytes, edge_id, scalar_bytes, scalar_text};

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
    /// How an instant (a TimeEvidence tick) becomes a civil date when a rule
    /// needs one (plan §7.7). Declared at genesis, never defaulted: a book
    /// without it refuses scheduled reversals (`auto_reverse_on`).
    pub time_zone_policy: Option<TimeZonePolicy>,
    /// The legal entities posting into the book (plan §4.1 `Book.entities`),
    /// declared at genesis. With more than one, `legal_entity` is a mandatory
    /// balancing dimension on every leg and the balance law holds per
    /// `(unit, legal_entity)` (FA-INV-01 `per-entity`, §5.2). Empty: the book
    /// is its single implicit entity and its bytes are unchanged.
    pub entities: Vec<LegalEntitySpec>,
    /// The book's opening date (plan §7.2, Period row): the first day of the
    /// first `Normal` period the book keeps live. Every `Normal` period that
    /// ends on or before it is generated `Historical`, born `Locked`, and
    /// admits only `Migration` entries (Appendix C). `None`: no period is
    /// historical and the book's bytes are unchanged.
    pub opening_date: Option<DateDay>,
}

/// One declared legal entity (plan §4.1 `LegalEntity`, §0.4 decision 1):
/// carries its code, name, and functional currency (`functional_unit`),
/// which is journaled at genesis and must equal `Book.base_unit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalEntitySpec {
    pub code: String,
    pub name: String,
    pub functional_unit: UnitId,
}

/// Enforce that a `LegalEntity`'s `functional_unit` is registered in `units`
/// and equals the book's `base_unit` (plan §0.4 decision 1, §4.1).
pub fn check_entity_functional_unit(
    entity_code: &str,
    functional_unit: UnitId,
    base_unit: UnitId,
    units: &UnitRegistry,
) -> Result<(), Refusal> {
    let Some(ent_unit) = units.get(functional_unit) else {
        return Err(Refusal::new(
            code::UNIT_UNREGISTERED,
            exit::REFUSAL,
            format!(
                "legal entity `{entity_code}` names unregistered functional_unit {}",
                functional_unit.0
            ),
            "plan §4.1, §4.4",
            "use a unit registered in the book",
        ));
    };
    if functional_unit != base_unit {
        let base_code = units
            .get(base_unit)
            .map_or_else(|| base_unit.0.to_string(), |u| u.code.clone());
        return Err(Refusal::new(
            code::UNIT_POLICY,
            exit::REFUSAL,
            format!(
                "legal entity `{entity_code}` has functional_unit `{}` which differs from the book's base_unit `{base_code}`; one functional currency per book (reporting currency exists only as Translation output in a consolidation book)",
                ent_unit.code
            ),
            "plan §0.4 decision 1, §4.1 LegalEntity.functional_unit",
            format!(
                "create a separate book with `--base-unit {}` for legal entity `{entity_code}` and consolidate via Concordat, or set `{entity_code}`'s functional_unit to `{base_code}`",
                ent_unit.code
            ),
        ));
    }
    Ok(())
}

const MAX_ENTITY_CODE_BYTES: usize = 32;
const MAX_ENTITIES: usize = 256;

/// The book's `time_zone_policy` (plan §7.7). This slice registers `Utc`
/// only; a zone with rules lands with the calendar-arithmetic slice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimeZonePolicy {
    Utc,
}

impl TimeZonePolicy {
    #[must_use]
    pub fn tag(self) -> u8 {
        match self {
            Self::Utc => 1,
        }
    }

    #[must_use]
    pub fn from_tag(tag: u8) -> Option<Self> {
        match tag {
            1 => Some(Self::Utc),
            _ => None,
        }
    }

    /// The civil date of an instant under this policy.
    #[must_use]
    pub fn civil_date(self, observed_utc_ns: u64) -> DateDay {
        const NS_PER_DAY: u64 = 86_400_000_000_000;
        match self {
            // u64::MAX / NS_PER_DAY = 213_503, well inside i32.
            Self::Utc => DateDay(i32::try_from(observed_utc_ns / NS_PER_DAY).unwrap_or(i32::MAX)),
        }
    }
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
    /// The canonical version-2 book bytes journaled on the root vertex.
    /// Version 2 keeps the version-1 fields and declares that every fiscal
    /// year's Period projections require an atomic CreatePeriods control.
    /// Version-1 books remain decodable with their legacy birth baseline.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.u16(2)
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
        // Trailing, and only when declared: a book without a policy,
        // entities or an opening date keeps the bytes it always had.
        // `[tz] [entities] [opening_date]`, each element present exactly when
        // it or a later one is declared (tz 0 = undeclared, an empty entity
        // list = none, each only before a later element).
        let opening = self.opening_date;
        if self.time_zone_policy.is_some() || !self.entities.is_empty() || opening.is_some() {
            w.u8(self.time_zone_policy.map_or(0, TimeZonePolicy::tag));
        }
        if !self.entities.is_empty() || opening.is_some() {
            w.list(&self.entities, |w, e| {
                w.str(&e.code).str(&e.name).u32(e.functional_unit.0);
            });
        }
        if let Some(day) = opening {
            w.i32(day.0);
        }
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    /// Enforce the one-functional-currency-per-book law (plan §0.4 decision 1,
    /// §4.1 `LegalEntity.functional_unit`) with a typed [`Refusal`] (`FA-REF-003`,
    /// exit 3 `refusal`) naming the fix.
    pub fn validate_functional_units(&self, units: &UnitRegistry) -> Result<(), Refusal> {
        for e in &self.entities {
            check_entity_functional_unit(&e.code, e.functional_unit, self.base_unit, units)?;
        }
        Ok(())
    }

    /// The structural law of a declaration (plan §4.1, §0.4 decision 1): entity
    /// codes are non-empty, at most 32 bytes, unique; at most 256 entities;
    /// names at most 256 bytes; every entity's `functional_unit` equals
    /// `self.base_unit`.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.len() > MAX_BOOK_NAME_BYTES {
            return Err(format!(
                "book name exceeds {MAX_BOOK_NAME_BYTES} bytes ({} bytes)",
                self.name.len()
            ));
        }
        if self.calendar.id.is_empty() || self.calendar.id.len() > MAX_CALENDAR_ID_BYTES {
            return Err(format!(
                "calendar id `{}` must be 1..={MAX_CALENDAR_ID_BYTES} bytes",
                self.calendar.id
            ));
        }
        self.calendar
            .validate()
            .map_err(|e| format!("calendar `{}`: {e}", self.calendar.id))?;
        if self.entities.len() > MAX_ENTITIES {
            return Err(format!(
                "a book declares at most {MAX_ENTITIES} legal entities"
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for e in &self.entities {
            if e.code.is_empty() || e.code.len() > MAX_ENTITY_CODE_BYTES {
                return Err(format!(
                    "legal entity code `{}` must be 1..={MAX_ENTITY_CODE_BYTES} bytes",
                    e.code
                ));
            }
            if e.name.len() > MAX_BOOK_NAME_BYTES {
                return Err(format!(
                    "legal entity `{}` has a name over {MAX_BOOK_NAME_BYTES} bytes",
                    e.code
                ));
            }
            if !seen.insert(e.code.as_str()) {
                return Err(format!("legal entity `{}` is declared twice", e.code));
            }
            if e.functional_unit != self.base_unit {
                return Err(format!(
                    "legal entity `{}` has functional_unit {} != book base_unit {}; one functional currency per book (plan §0.4 decision 1): create a separate book for `{}` and consolidate via Concordat",
                    e.code, e.functional_unit.0, self.base_unit.0, e.code
                ));
            }
        }
        if let Some(day) = self.opening_date {
            let starts_normal = self
                .calendar
                .fiscal_year_of(day)
                .and_then(|fy| self.calendar.periods_for_year(fy))
                .is_ok_and(|ps| {
                    ps.iter()
                        .any(|p| p.kind == PeriodKind::Normal && p.start == day)
                });
            if !starts_normal {
                return Err(format!(
                    "opening_date {} is not the first day of a Normal period of calendar `{}`",
                    day.render(),
                    self.calendar.id
                ));
            }
        }
        Ok(())
    }

    /// The kind and birth state of a calendar period in this book (plan
    /// §7.2): a `Normal` period ending on or before the opening date is
    /// `Historical` and born `Locked`; a special period the registered
    /// `pre_opening` rule governs (ending on or before the opening date)
    /// keeps its kind and is born in the rule's state; every other period
    /// is born `Future`.
    #[must_use]
    pub fn birth(
        &self,
        period: &PeriodDef,
        pre_opening: &fa_registry::PreOpeningRule,
    ) -> (PeriodKind, PeriodState) {
        match self.opening_date {
            Some(day) if period.kind == PeriodKind::Normal && period.end <= day => {
                (PeriodKind::Historical, PeriodState::Locked)
            }
            _ if pre_opening.governs(period.kind, period.end, self.opening_date) => {
                (period.kind, pre_opening.born)
            }
            _ => (period.kind, PeriodState::Future),
        }
    }

    /// The declared entity whose `dimension_set` value is `value`.
    #[must_use]
    pub fn entity_of(&self, value: VId) -> Option<&LegalEntitySpec> {
        self.entities
            .iter()
            .find(|e| fa_model::entity_value_vid(self.book_id, &e.code) == value)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let spec = (|| -> Result<Self, DecodeError> {
            let v = r.u16("book.version")?;
            if !matches!(v, 1 | 2) {
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
            let time_zone_policy = if r.remaining() > 0 {
                match r.u8("book.time_zone_policy")? {
                    // 0 = undeclared, written only before a later element:
                    // a lone 0 is not a canonical encoding.
                    0 if r.remaining() == 0 => return Err(r.invalid("book.time_zone_policy")),
                    0 => None,
                    t => Some(
                        TimeZonePolicy::from_tag(t)
                            .ok_or_else(|| r.bad_tag("book.time_zone_policy", t))?,
                    ),
                }
            } else {
                None
            };
            let entities = if r.remaining() > 0 {
                let list = r.list(MAX_ENTITIES, "book.entities", |r| {
                    Ok(LegalEntitySpec {
                        code: r
                            .str(MAX_ENTITY_CODE_BYTES, "book.entity.code")?
                            .to_string(),
                        name: r.str(MAX_BOOK_NAME_BYTES, "book.entity.name")?.to_string(),
                        functional_unit: UnitId(r.u32("book.entity.functional_unit")?),
                    })
                })?;
                // An empty list is written only before an opening date.
                if list.is_empty() && r.remaining() == 0 {
                    return Err(r.invalid("book.entities"));
                }
                list
            } else {
                Vec::new()
            };
            let opening_date = if r.remaining() > 0 {
                Some(DateDay(r.i32("book.opening_date")?))
            } else {
                None
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
                time_zone_policy,
                entities,
                opening_date,
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
    if units.get(spec.base_unit).is_none() {
        return Err(KernelError::Corrupt(format!(
            "book.base_unit {} is absent from the genesis unit table",
            spec.base_unit.0
        )));
    }
    let units_digest = fa_model::unit::unit_table_digest(units)
        .map_err(|e| KernelError::Corrupt(format!("unit table: {e}")))?;
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
        (
            property::UNIT_TABLE_DIGEST,
            scalar_bytes("unit_table_digest", units_digest.to_vec())?,
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(bvid, vec![label::BOOK], props);
    crate::outcome::stage_genesis(&mut batch, spec.book_id)?;
    for (id, unit) in units.iter() {
        let definition = fa_model::UnitDefinition {
            id,
            unit: unit.clone(),
        };
        let payload = definition
            .canonical_bytes()
            .map_err(|e| KernelError::Corrupt(format!("unit {}: {e}", unit.code)))?;
        let uvid = unit_vid(spec.book_id, &format!("{}@v{}", unit.code, unit.version));
        let mut props = vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes("unit._fa_payload", payload)?,
            ),
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
    if spec.entities.is_empty() {
        return Ok(db.write(&ctx.commit(), batch).await?);
    }
    // Declared legal entities (plan §4.1): each a `LegalEntity`, the book's
    // legal-entity `Dimension` (kind LegalEntity, balancing), and one
    // `DimensionValue` per entity, bound to it by `REPRESENTS` — the value a
    // leg's `dimension_set` names. A second relation is a second batch,
    // staged in order in one commit.
    if let Err(why) = spec.validate() {
        return Err(KernelError::Corrupt(format!("invalid book spec: {why}")));
    }
    let book_id = scalar_bytes("book_id", spec.book_id.0.to_vec())?;
    let dim = fa_model::dimension_vid(spec.book_id, fa_model::LEGAL_ENTITY_DIMENSION_CODE);
    let dim_id = CanonicalScalar::Int(i64::from(fa_model::LEGAL_ENTITY_DIMENSION));
    let mut props = vec![
        (property::BOOK_ID, book_id.clone()),
        (
            property::CODE,
            scalar_text("code", fa_model::LEGAL_ENTITY_DIMENSION_CODE)?,
        ),
        (property::NAME, scalar_text("name", "Legal entity")?),
        (property::DIMENSION_ID, dim_id.clone()),
        (
            property::DIMENSION_KIND,
            CanonicalScalar::Int(DIMENSION_KIND_LEGAL_ENTITY),
        ),
    ];
    props.sort_by_key(|(k, _)| k.0);
    batch.create_vertex(dim, vec![label::DIMENSION], props);
    batch.add_edge(edge_id(relation::IN_BOOK, dim, bvid), dim, bvid, vec![]);
    let mut represents = WriteBatch::new(relation::REPRESENTS);
    for e in &spec.entities {
        let evid = fa_model::legal_entity_vid(spec.book_id, &e.code);
        let value = fa_model::entity_value_vid(spec.book_id, &e.code);
        let mut props = vec![
            (property::BOOK_ID, book_id.clone()),
            (property::CODE, scalar_text("code", &e.code)?),
            (property::NAME, scalar_text("name", &e.name)?),
            (
                property::UNIT_ID,
                CanonicalScalar::Int(i64::from(e.functional_unit.0)),
            ),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(evid, vec![label::LEGAL_ENTITY], props);
        batch.add_edge(edge_id(relation::IN_BOOK, evid, bvid), evid, bvid, vec![]);
        let mut props = vec![
            (property::BOOK_ID, book_id.clone()),
            (property::CODE, scalar_text("code", &e.code)?),
            (property::DIMENSION_ID, dim_id.clone()),
        ];
        props.sort_by_key(|(k, _)| k.0);
        batch.create_vertex(value, vec![label::DIMENSION_VALUE], props);
        batch.add_edge(edge_id(relation::IN_BOOK, value, bvid), value, bvid, vec![]);
        represents.add_edge(
            edge_id(relation::REPRESENTS, evid, value),
            evid,
            value,
            vec![],
        );
    }
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    txn.write_ordered(db, vec![batch, represents])?;
    Ok(txn.commit(db, &ctx.commit()).await?)
}

/// `Dimension.kind` of the legal-entity dimension (plan §4.1 Dimension row:
/// `kind: {LegalEntity, …}`, balancing).
pub const DIMENSION_KIND_LEGAL_ENTITY: i64 = 1;

/// The book's opening date, read inside `txn` from the root's immutable
/// `_fa_payload` alone (a point witness that never conflicts: the root's
/// moving pointers are other properties).
pub(crate) fn opening_date_in<V: asupersync::fs::Vfs + Clone>(
    txn: &fgdb::WriteTxn,
    db: &Database<V>,
) -> Result<Option<DateDay>, KernelError> {
    match txn.vertex_property(db, book_root(), property::FA_PAYLOAD)? {
        Some(CanonicalScalar::Bytes(b)) => Ok(BookSpec::decode(b.as_slice())?.opening_date),
        other => Err(KernelError::Corrupt(format!("book._fa_payload: {other:?}"))),
    }
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

/// Reconstruct the runtime unit table from the complete journaled payloads,
/// checking every mirror and the binary's supported definitions. Additional
/// binary rows are allowed but are not installed into an existing book.
/// Missing pre-payload metadata is refused; it is never inferred from the
/// binary that happened to open the book (fa-nnm, fa-k1u).
pub fn read_units<V: asupersync::fs::Vfs + Clone>(
    db: &Database<V>,
    book_id: Id128,
    supported: &UnitRegistry,
) -> Result<UnitRegistry, KernelError> {
    use crate::rows::{int, prop, text};

    let pre_payload = |what: &str| {
        KernelError::Corrupt(format!(
            "pre-payload unit table: {what}; this binary cannot infer missing unit facts, and no backfill exists before 1.0: keep the book unchanged and open it with its creating binary"
        ))
    };
    let root = db
        .vertex(book_root())?
        .ok_or_else(|| KernelError::Corrupt("unit table has no Book root".into()))?;
    let expected_digest = match prop(&root, property::UNIT_TABLE_DIGEST) {
        None => return Err(pre_payload("Book.unit_table_digest is absent")),
        Some(CanonicalScalar::Bytes(bytes)) if bytes.as_slice().len() == 32 => {
            bytes.as_slice().to_vec()
        }
        _ => {
            return Err(KernelError::Corrupt(
                "Book.unit_table_digest must contain 32 bytes".into(),
            ));
        }
    };
    let mut definitions = std::collections::BTreeMap::new();
    for vid in db.in_neighbours(book_root(), relation::IN_BOOK)? {
        let Some(row) = db.vertex(vid)? else {
            continue;
        };
        if !row.labels.contains(&label::UNIT) {
            continue;
        }
        let payload = match prop(&row, property::FA_PAYLOAD) {
            None => {
                return Err(pre_payload(&format!(
                    "unit {vid:?} has no canonical payload"
                )));
            }
            Some(CanonicalScalar::Bytes(bytes)) => bytes.as_slice(),
            _ => {
                return Err(KernelError::Corrupt(format!(
                    "unit {vid:?}._fa_payload must be bytes"
                )));
            }
        };
        let definition = fa_model::UnitDefinition::decode(payload)
            .map_err(|e| KernelError::Corrupt(format!("unit {vid:?}: {e}")))?;
        let id = definition.id;
        let unit = &definition.unit;
        let mismatch = |field: &str| {
            KernelError::Corrupt(format!(
                "unit {} ({}@v{}) {field} differs from its journaled definition; refuse reinterpretation of historical amounts",
                id.0, unit.code, unit.version
            ))
        };
        if bytes(&row, property::BOOK_ID, "unit.book_id")? != book_id.0 {
            return Err(mismatch("book_id mirror"));
        }
        if int(&row, property::UNIT_ID, "unit.unit_id")? != i64::from(id.0) {
            return Err(mismatch("id mirror"));
        }
        if text(&row, property::CODE, "unit.code")? != unit.code {
            return Err(mismatch("code mirror"));
        }
        if int(&row, property::VERSION, "unit.version")? != i64::from(unit.version) {
            return Err(mismatch("version mirror"));
        }
        if int(&row, property::SCALE, "unit.scale")? != i64::from(unit.scale) {
            return Err(mismatch("scale mirror"));
        }
        if vid != unit_vid(book_id, &format!("{}@v{}", unit.code, unit.version)) {
            return Err(mismatch("vertex identity"));
        }
        let Some(binary) = supported.get(id) else {
            return Err(mismatch("binary registry id (unsupported unit)"));
        };
        if binary.code != unit.code {
            return Err(mismatch("binary code"));
        }
        if binary.version != unit.version {
            return Err(mismatch("binary version"));
        }
        if binary.scale != unit.scale {
            return Err(mismatch("binary scale"));
        }
        if binary.kind != unit.kind {
            return Err(mismatch("binary kind/ISO 4217"));
        }
        if binary.rounding_default != unit.rounding_default {
            return Err(mismatch("binary default rounding law"));
        }
        if definitions.insert(id, definition.unit).is_some() {
            return Err(KernelError::Corrupt(format!(
                "duplicate journaled unit id {}",
                id.0
            )));
        }
    }
    if definitions.is_empty() {
        return Err(KernelError::Corrupt("journaled unit table is empty".into()));
    }
    let mut units = UnitRegistry::empty();
    for (id, unit) in definitions {
        if usize::try_from(id.0).ok() != Some(units.len()) {
            return Err(KernelError::Corrupt(format!(
                "journaled unit table has a gap before id {}",
                id.0
            )));
        }
        let assigned = units
            .register(unit)
            .map_err(|e| KernelError::Corrupt(format!("journaled unit {}: {e}", id.0)))?;
        if assigned != id {
            return Err(KernelError::Corrupt(format!(
                "duplicate journaled unit definition at id {}",
                id.0
            )));
        }
    }
    let actual_digest = fa_model::unit::unit_table_digest(&units)
        .map_err(|e| KernelError::Corrupt(format!("unit table: {e}")))?;
    if expected_digest != actual_digest {
        return Err(KernelError::Corrupt(
            "journaled unit table differs from Book.unit_table_digest; a definition or membership is missing or changed".into(),
        ));
    }
    Ok(units)
}

/// Period creation is an authorized, journaled schema effect.
pub use crate::period_creation::create_periods;

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
    capability: &crate::Capability,
) -> Outcome<ChartInstalled> {
    let key = fa_policy::sod::control_key("SchemaControl", None, "ChartInstall");
    let Some(op) = crate::policy::steward()?.preparer_op(&key) else {
        return Err(KernelError::Corrupt(
            "sod_policy.toml has no schema-chart-install rule".into(),
        ));
    };
    if let Err(denial) = fa_policy::admit_within(
        capability,
        &fa_policy::Intent {
            principal: principal_ref,
            trunk: true,
            op,
            book: book.book_id,
            legs: &[],
        },
        &fa_policy::Reach::whole_book(true),
        None,
    ) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        return Ok(Err(crate::policy::refusal(&denial)));
    }
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
        if a.normal_balance > 1 {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "account `{}` has invalid normal_balance {}",
                    a.code, a.normal_balance
                ),
                "Appendix A Account.normal_balance",
                "use 0 (Debit) or 1 (Credit)",
            )));
        }
        if let UnitPolicy::Single(unit) = a.unit_policy
            && book.units.get(unit).is_none()
        {
            return Ok(Err(Refusal::new(
                code::UNIT_UNREGISTERED,
                exit::REFUSAL,
                format!("account `{}` names unregistered unit id {}", a.code, unit.0),
                "plan §4.3, §4.4",
                "use a unit registered in the book",
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
    // The chart is a forest of unique codes (plan §4.3): a code names one
    // account, and no account is its own ancestor. Both are refused here,
    // before any write, rather than surfacing as an identity collision or a
    // cycle a later fold would walk forever.
    let mut codes = std::collections::BTreeSet::new();
    for a in accounts {
        if !codes.insert(a.code.as_str()) {
            return Ok(Err(Refusal::new(
                code::STRUCTURE,
                exit::USAGE,
                format!(
                    "account code `{}` appears more than once in the chart",
                    a.code
                ),
                "plan §4.3 (an account's code is its identity)",
                "keep one row per account code",
            )));
        }
    }
    for a in accounts {
        let mut at = a;
        for _ in 0..accounts.len() {
            let Some(parent) = &at.parent_code else { break };
            if *parent == a.code {
                return Ok(Err(Refusal::new(
                    code::STRUCTURE,
                    exit::USAGE,
                    format!(
                        "account `{}` is its own ancestor: its parent chain cycles",
                        a.code
                    ),
                    "plan §4.3 (the chart is a forest)",
                    "break the cycle: give one account in it another parent, or none",
                )));
            }
            match accounts.iter().find(|x| x.code == *parent) {
                Some(next) => at = next,
                None => break,
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
            control_kind: fa_model::ControlKind::CHART_INSTALL,
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
    let proposal_digest = proposal.proposal_digest()?;
    let entry: Entry = proposal.seal(Vec::new(), None)?;
    let evid = entry_vid(
        book.book_id,
        &principal_ref.0.to_le_bytes(),
        idempotency_key,
    );
    // Verify current authority before observing existing periods, and keep
    // revocation and policy witnesses in the same transaction as the chart.
    let txn_cx = ctx.txn();
    let mut txn = db.begin(&txn_cx)?;
    if let Err(refusal) = crate::policy::capability_witness(&txn, db, book, capability)? {
        txn.abort();
        return Ok(Err(refusal));
    }
    let epoch = crate::policy::epoch_witness(&txn, db)?;
    if let Err(refusal) = crate::policy::authorize_approvals(
        &txn,
        db,
        book,
        &[],
        &proposal_digest,
        epoch,
        &key,
        0,
        fa_policy::sod::Party {
            principal: principal_ref,
            profile: capability.profile(),
        },
    )? {
        txn.abort();
        return Ok(Err(refusal));
    }
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
    // An existing identity is the same lawful refusal whether the substrate
    // reports it while staging (a re-imported chart: its vertices are live)
    // or at commit; it is never a foundation failure.
    let existing = || {
        Refusal::new(
            code::STRUCTURE,
            exit::USAGE,
            "an account or control entry with this identity already exists",
            "plan §4.9 (identities are derived; a duplicate is a point conflict)",
            "use a fresh idempotency key and omit accounts already installed",
        )
    };
    if let Err(e) = txn.write_ordered(db, vec![batch, in_book]) {
        txn.abort();
        return match e {
            fgdb::WriteTxnError::Write(
                fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
            ) => Ok(Err(existing())),
            e => Err(e.into()),
        };
    }
    if let Err(denial) = fa_policy::current(capability, db.frontier()?) {
        txn.abort();
        return Ok(Err(crate::policy::refusal(&denial)));
    }
    match txn.commit(db, &ctx.commit()).await {
        Ok(seq) => Ok(Ok(ChartInstalled {
            recorded_at: seq,
            control_entry: evid,
            accounts: accounts.len(),
        })),
        Err(fgdb::WriteTxnError::Write(
            fgdb::WriteError::AlreadyLive { .. } | fgdb::WriteError::IdentitySpent { .. },
        )) => Ok(Err(existing())),
        Err(fgdb::WriteTxnError::Write(fgdb::WriteError::FirstCommitterWins {
            detail, ..
        })) => Ok(Err(Refusal::new(
            code::CONFLICT,
            exit::CONFLICT,
            format!("chart installation's authority or schema witness changed: {detail}"),
            "FA-INV-10 / FG-LAW-FCW-01",
            "retry chart installation against the current policy and book",
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
                time_zone_policy: None,
                entities: Vec::new(),
                opening_date: None,
            };
            let bytes = spec.canonical_bytes().unwrap();
            assert_eq!(BookSpec::decode(&bytes).unwrap(), spec);
            assert!(BookSpec::decode(&bytes[..bytes.len() - 1]).is_err());
            // Declared entities trail the policy byte (0 = undeclared); the
            // bytes before them are unchanged; a lone 0 is not canonical.
            let entities = vec![
                LegalEntitySpec {
                    code: "US".into(),
                    name: "US Co".into(),
                    functional_unit: UnitId(3),
                },
                LegalEntitySpec {
                    code: "UK".into(),
                    name: "UK Ltd".into(),
                    functional_unit: UnitId(3),
                },
            ];
            let multi = BookSpec {
                entities: entities.clone(),
                ..spec.clone()
            };
            let mb = multi.canonical_bytes().unwrap();
            assert_eq!(&mb[..bytes.len()], bytes.as_slice());
            assert_eq!(mb[bytes.len()], 0);
            assert_eq!(BookSpec::decode(&mb).unwrap(), multi);
            let both = BookSpec {
                time_zone_policy: Some(TimeZonePolicy::Utc),
                entities,
                ..spec.clone()
            };
            assert_eq!(
                BookSpec::decode(&both.canonical_bytes().unwrap()).unwrap(),
                both
            );
            let mut lone_zero = bytes.clone();
            lone_zero.push(0);
            assert!(BookSpec::decode(&lone_zero).is_err());
            assert!(multi.validate().is_ok());
            let twice = BookSpec {
                entities: vec![multi.entities[0].clone(), multi.entities[0].clone()],
                ..spec.clone()
            };
            assert!(twice.validate().unwrap_err().contains("twice"));
            // Planted negative: a LegalEntity whose functional_unit differs from
            // Book.base_unit is refused with the Concordat fix (plan §0.4 decision 1).
            let units = UnitRegistry::with_defaults();
            assert!(multi.validate_functional_units(&units).is_ok());
            let mismatched = BookSpec {
                entities: vec![LegalEntitySpec {
                    code: "EU".into(),
                    name: "EU Sub".into(),
                    functional_unit: UnitId(1),
                }],
                ..spec.clone()
            };
            let err_msg = mismatched.validate().unwrap_err();
            assert!(err_msg.contains("Concordat"), "{err_msg}");
            let refusal = mismatched.validate_functional_units(&units).unwrap_err();
            assert_eq!(refusal.code, code::UNIT_POLICY);
            assert_eq!(refusal.exit, exit::REFUSAL);
            assert!(refusal.fix.contains("Concordat"), "{}", refusal.fix);
            // A declared policy is one trailing byte; the bytes without it
            // are unchanged, and an unregistered tag is refused.
            let declared = BookSpec {
                time_zone_policy: Some(TimeZonePolicy::Utc),
                ..spec.clone()
            };
            let with = declared.canonical_bytes().unwrap();
            assert_eq!(&with[..bytes.len()], bytes.as_slice());
            assert_eq!(with.len(), bytes.len() + 1);
            assert_eq!(BookSpec::decode(&with).unwrap(), declared);
            let mut unknown = bytes.clone();
            unknown.push(9);
            assert!(BookSpec::decode(&unknown).is_err());
        }
    }

    /// The opening date (plan §7.2) trails the spec canonically, is the first
    /// day of a Normal period, and decides each period's birth: a Normal
    /// period ending on or before it is Historical and born Locked; the
    /// special periods and the live ones are born Future.
    #[test]
    fn the_opening_date_trails_canonically_and_births_historical_periods() {
        let spec = BookSpec {
            book_id: Id128([5; 16]),
            name: "Go Live Co".into(),
            base_unit: UnitId(1),
            calendar: FiscalCalendar {
                id: "cy".into(),
                kind: CalendarKind::Monthly12 {
                    year_start_month: 1,
                },
                adjustment_periods: 1,
            },
            time_zone_policy: None,
            entities: Vec::new(),
            opening_date: None,
        };
        let bare = spec.canonical_bytes().unwrap();
        let july = DateDay::from_ymd(2026, 7, 1).unwrap();
        let live = BookSpec {
            opening_date: Some(july),
            ..spec.clone()
        };
        let bytes = live.canonical_bytes().unwrap();
        assert_eq!(
            &bytes[..bare.len()],
            bare.as_slice(),
            "earlier bytes unchanged"
        );
        assert_eq!(bytes[bare.len()], 0, "tz undeclared before the date");
        assert_eq!(BookSpec::decode(&bytes).unwrap(), live);
        // Without the date, the empty entity list it needed is not canonical.
        assert!(BookSpec::decode(&bytes[..bytes.len() - 4]).is_err());
        let everything = BookSpec {
            time_zone_policy: Some(TimeZonePolicy::Utc),
            entities: vec![LegalEntitySpec {
                code: "US".into(),
                name: "US Co".into(),
                functional_unit: UnitId(1),
            }],
            ..live.clone()
        };
        assert_eq!(
            BookSpec::decode(&everything.canonical_bytes().unwrap()).unwrap(),
            everything
        );
        assert!(live.validate().is_ok());
        let mid_month = BookSpec {
            opening_date: Some(DateDay::from_ymd(2026, 7, 15).unwrap()),
            ..spec.clone()
        };
        assert!(
            mid_month
                .validate()
                .unwrap_err()
                .contains("not the first day of a Normal period")
        );
        let classes = fa_registry::EntryClasses::embedded().unwrap();
        let matrix = fa_registry::Admissibility::embedded(&classes).unwrap();
        let rule = matrix.pre_opening().expect("pre_opening");
        let periods = live.calendar.periods_for_year(2026).unwrap();
        let birth = |code: &str| {
            let p = periods.iter().find(|p| p.code == code).expect(code);
            live.birth(p, rule)
        };
        assert_eq!(
            birth("FY2026-P06"),
            (PeriodKind::Historical, PeriodState::Locked)
        );
        assert_eq!(
            birth("FY2026-P01"),
            (PeriodKind::Historical, PeriodState::Locked)
        );
        assert_eq!(
            birth("FY2026-P07"),
            (PeriodKind::Normal, PeriodState::Future)
        );
        // The year's Opening period ends January 2, before the July opening
        // date: a pre-opening special period, born Locked, kind kept.
        assert_eq!(
            birth("FY2026-OPEN"),
            (PeriodKind::Opening, PeriodState::Locked)
        );
        assert_eq!(
            birth("FY2026-A1"),
            (PeriodKind::Adjustment, PeriodState::Future)
        );
        let before = live.calendar.periods_for_year(2025).unwrap();
        assert!(
            before
                .iter()
                .filter(|p| p.kind == PeriodKind::Normal)
                .all(|p| live.birth(p, rule) == (PeriodKind::Historical, PeriodState::Locked))
        );
        // FY2025's special periods (its year-end close included) precede the
        // opening date: kind kept, born Locked.
        assert!(
            before
                .iter()
                .filter(|p| p.kind != PeriodKind::Normal)
                .all(|p| live.birth(p, rule) == (p.kind, PeriodState::Locked))
        );
        // No opening date: every period is born as the calendar defines it.
        assert!(
            periods
                .iter()
                .all(|p| spec.birth(p, rule) == (p.kind, PeriodState::Future))
        );
    }
}
