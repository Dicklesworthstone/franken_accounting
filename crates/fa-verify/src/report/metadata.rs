//! Metadata reconstructed from authenticated journal controls, never from
//! producer-supplied account or period projections.

use super::{ReportError, Selection, failed, text};
use crate::codec::Reader;
use crate::envelope::{
    LeafEnvelope, MAX_ENVELOPE_LIST, MAX_RECORD_BYTES, proposal_after_legs, skip_control,
    skip_erasable, skip_origin,
};
use std::collections::{BTreeMap, BTreeSet};

// Registered fa:entry:v1 TimeTick and derived-identity bounds, independently
// encoded here rather than importing the producer's model or decoder.
const MAX_TICK_UTC_NS: u64 = 9_223_372_036_854_775_807;
const MAX_TICK_KEY_BYTES: usize = 64;

pub(super) struct EntryInfo<'a> {
    pub schema: Option<(u16, &'a [u8])>,
    pub time_tick: Option<super::temporal::TimeObservation>,
    pub period: Option<(&'a str, &'a str)>,
    pub resolution: Option<(u128, [u8; 32])>,
    pub supersession: Vec<(u128, [u8; 32], u8)>,
    pub supersession_reasons: Vec<u16>,
    pub evidence: Vec<([u8; 32], [u8; 32], u8)>,
    pub identity: u128,
    /// Before replacement-pair identities were target-derived, the immutable
    /// corrected member used its ordinary key identity. Both encodings name
    /// the same authenticated payload, never an arbitrary producer alias.
    pub(super) legacy_identity: Option<u128>,
}

impl EntryInfo<'_> {
    pub fn identities(&self) -> impl Iterator<Item = u128> + '_ {
        std::iter::once(self.identity).chain(
            self.legacy_identity
                .filter(|legacy| *legacy != self.identity),
        )
    }
    pub fn matches_identity(&self, identity: u128) -> bool {
        self.identity == identity || self.legacy_identity == Some(identity)
    }
}

fn target_identity(domain: &[u8], target: u128) -> u128 {
    let hash = crate::blake3::hash_parts(domain, &[&target.to_le_bytes()]);
    let mut low = [0; 16];
    low.copy_from_slice(&hash[..16]);
    u128::from_le_bytes(low)
}

fn framed_identity(domain: &[u8], parts: &[&[u8]]) -> u128 {
    let mut raw = Vec::new();
    for part in parts {
        raw.extend_from_slice(&(part.len() as u32).to_le_bytes());
        raw.extend_from_slice(part);
    }
    let digest = crate::blake3::hash_parts(domain, &[&raw]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

pub(super) fn entry_info<'a>(
    proposal: &'a [u8],
    envelope: &LeafEnvelope,
) -> Result<EntryInfo<'a>, ReportError> {
    let mut first = Reader::new(proposal);
    first.u16("entry.major")?;
    let minor = first.u16("entry.minor")?;
    first.fixed::<16>("entry.book")?;
    first.fixed::<16>("entry.branch")?;
    first.u16("entry.class")?;
    first.i32("entry.effective")?;
    if first.present("entry.document_date")? {
        first.i32("entry.document_date")?;
    }
    skip_erasable(&mut first, "entry.description")?;
    let period = if first.present("entry.period")? {
        Some((
            text(&mut first, 128, "entry.calendar")?,
            text(&mut first, 128, "entry.period")?,
        ))
    } else {
        None
    };
    let mut r = proposal_after_legs(proposal)?;
    let mut schema = None;
    let mut time_tick = None;
    if r.present("entry.control")? {
        let mut probe = Reader::new(&proposal[proposal.len() - r.remaining()..]);
        let tag = probe.u8("control.tag")?;
        if tag == 1 {
            if envelope.class != 17 {
                return Err(failed(
                    "schema_history",
                    "schema payload outside SchemaControl",
                ));
            }
            schema = Some((
                probe.u16("control.kind")?,
                probe.bytes(MAX_RECORD_BYTES, "control.body")?,
            ));
        } else if tag == 4 {
            let tick = super::temporal::TimeObservation {
                recorded_at: envelope.commit_seq,
                observed_utc_ns: probe.u64("control.observed_utc_ns")?,
                source: probe.u8("control.source")?,
                monotonic_ok: probe.present("control.monotonic_ok")?,
            };
            if tick.source > 2 || tick.observed_utc_ns > MAX_TICK_UTC_NS {
                return Err(failed(
                    "time_history",
                    "TimeTick source or observed UTC nanoseconds exceeds its registered bound",
                ));
            }
            time_tick = Some(tick);
        }
        skip_control(&mut r)?;
    }
    if (envelope.class == 19) != time_tick.is_some() {
        return Err(failed(
            "time_history",
            "TimeControl class and TimeTick payload disagree",
        ));
    }
    if time_tick.is_some() && (!envelope.account_vids.is_empty() || !envelope.unit_ids.is_empty()) {
        return Err(failed("time_history", "TimeTick carries monetary legs"));
    }
    let n = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
    if time_tick.is_some() && n != 0 {
        return Err(failed("time_history", "TimeTick carries monetary totals"));
    }
    for _ in 0..n {
        r.fixed::<36>("unit_total")?;
    }
    if r.present("entry.base_totals")? {
        r.fixed::<68>("base_totals")?;
        let n = r.count(MAX_ENVELOPE_LIST, 32, "base_totals.rates")?;
        for _ in 0..n {
            r.fixed::<32>("rate")?;
        }
        if r.present("base_totals.residual")? {
            r.fixed::<22>("residual")?;
        }
    }
    let key = r.bytes(MAX_RECORD_BYTES, "entry.idempotency_key")?;
    if time_tick.is_some() && (key.is_empty() || key.len() > MAX_TICK_KEY_BYTES) {
        return Err(failed(
            "time_history",
            "TimeTick identity requires a key of 1..=64 bytes",
        ));
    }
    let mut probe = Reader::new(&proposal[proposal.len() - r.remaining()..]);
    let origin = probe.u8("origin.tag")?;
    let migration = if origin == 2 {
        Some(probe.u128("origin.run")?)
    } else {
        None
    };
    let schedule = if origin == 5 {
        Some((
            probe.u128("origin.schedule")?,
            probe.u8("origin.trigger")?,
            probe.u128("origin.trigger_ref")?,
        ))
    } else {
        None
    };
    if (origin == 2) != (envelope.class == 12) {
        return Err(failed(
            "migration_visibility",
            "migration origin and class disagree",
        ));
    }
    if let Some((kind, _)) = schema
        && (origin != 3 || probe.u16("origin.control_kind")? != if kind == 13 { 13 } else { 1 })
    {
        return Err(failed(
            "schema_history",
            "schema change has an unrelated control origin",
        ));
    }
    if let Some(tick) = time_tick {
        if origin != 3 || probe.u16("origin.control_kind")? != 4 {
            return Err(failed(
                "time_history",
                "TimeTick has an unrelated control origin",
            ));
        }
        let expected = crate::blake3::hash_parts(b"", &[&tick.observed_utc_ns.to_le_bytes()]);
        if probe.fixed::<32>("origin.spec_body_digest")? != expected {
            return Err(failed(
                "time_history",
                "TimeTick origin digest does not bind its observed UTC nanoseconds",
            ));
        }
    }
    skip_origin(&mut r)?;
    let principal = r.u128("entry.principal")?;
    let key_identity = framed_identity(
        b"fa:vid:entry:v1",
        &[&envelope.book_id, &principal.to_le_bytes(), key],
    );
    if r.present("entry.session")? {
        r.u128("entry.session")?;
    }
    let n = r.count(MAX_ENVELOPE_LIST, 65, "entry.evidence")?;
    let mut evidence = Vec::with_capacity(n);
    for _ in 0..n {
        evidence.push((
            r.fixed("evidence.document_oid")?,
            r.fixed("evidence.doc_commit")?,
            r.u8("evidence.role")?,
        ));
    }
    let n = r.count(MAX_ENVELOPE_LIST, 51, "entry.supersession")?;
    let mut supersession = Vec::with_capacity(n);
    let mut supersession_reasons = Vec::with_capacity(n);
    for _ in 0..n {
        let target = r.u128("supersession.target")?;
        let digest = r.fixed("supersession.digest")?;
        let kind = r.u8("supersession.kind")?;
        supersession_reasons.push(r.u16("supersession.reason")?);
        if !(1..=6).contains(&kind) {
            return Err(failed("entry_lineage", "unknown supersession kind"));
        }
        supersession.push((target, digest, kind));
    }
    let mut resolution = None;
    if r.present("entry.pending")? {
        if time_tick.is_some() {
            return Err(failed("time_history", "TimeTick carries a pending block"));
        }
        if r.present("pending.timeout")? {
            r.u64("pending.timeout")?;
        }
        if r.present("pending.resolution")? {
            resolution = Some((r.u128("pending.target")?, r.fixed("pending.digest")?));
        }
        if r.present("pending.disposition")? {
            match r.u8("pending.disposition")? {
                1 => {}
                2 => {
                    r.u64("pending.expiry")?;
                }
                3 => {
                    let n = r.count(MAX_ENVELOPE_LIST, 2, "pending.posted_ordinals")?;
                    for _ in 0..n {
                        r.u16("pending.ordinal")?;
                    }
                }
                _ => return Err(failed("pending_resolution", "unknown pending disposition")),
            }
        }
    }
    for field in ["entry.external_ids", "entry.tags"] {
        let n = r.count(if field == "entry.tags" { 32 } else { 256 }, 65, field)?;
        for _ in 0..n {
            r.bytes(64, "entry.key")?;
            skip_erasable(&mut r, "entry.value")?;
        }
    }
    let mut recurring = None;
    if minor >= 1 {
        let n = r.count(MAX_ENVELOPE_LIST, 6, "entry.extensions")?;
        let mut previous = None;
        for _ in 0..n {
            let tag = r.u16("extension.tag")?;
            let bytes = r.bytes(MAX_RECORD_BYTES, "extension.body")?;
            if previous.is_some_and(|last| last >= tag) {
                return Err(failed(
                    "entry_identity",
                    "extensions are not strictly ordered",
                ));
            }
            previous = Some(tag);
            if tag == 31 {
                let mut marker = Reader::new(bytes);
                if marker.u16("recurring.version")? != 1 {
                    return Err(failed(
                        "entry_identity",
                        "unknown recurring occurrence version",
                    ));
                }
                let source = marker.u128("recurring.schedule")?;
                let index = marker.u64("recurring.index")?;
                let tick = marker.u128("recurring.tick")?;
                marker.finish("recurring occurrence")?;
                if envelope.class != 1 || schedule != Some((source, 0, tick)) {
                    return Err(failed(
                        "entry_identity",
                        "recurring marker differs from its schedule origin",
                    ));
                }
                recurring = Some(framed_identity(
                    b"fa:vid:recurring:v1",
                    &[&source.to_le_bytes(), &index.to_le_bytes()],
                ));
            }
        }
    }
    r.finish("report entry metadata")?;
    let (mut identity, legacy_identity) = match envelope.class {
        4 => match supersession.as_slice() {
            [(target, _, 1)] => (target_identity(b"fa:vid:reversal:v1", *target), None),
            _ => {
                return Err(failed(
                    "entry_identity",
                    "reversal requires one Reverses target",
                ));
            }
        },
        5 => match supersession.as_slice() {
            [(target, _, 2)] => (
                target_identity(b"fa:vid:replacement:v1", *target),
                Some(key_identity),
            ),
            _ => {
                return Err(failed(
                    "entry_identity",
                    "replacement requires one Replaces target",
                ));
            }
        },
        3 => match resolution {
            Some((target, _)) => (target_identity(b"fa:vid:resolution:v1", target), None),
            None => {
                return Err(failed(
                    "entry_identity",
                    "resolution requires a pending target",
                ));
            }
        },
        12 => (
            framed_identity(
                b"fa:vid:migration-entry:v1",
                &[
                    &envelope.book_id,
                    &migration
                        .ok_or_else(|| failed("entry_identity", "migration requires its run"))?
                        .to_le_bytes(),
                    key,
                ],
            ),
            None,
        ),
        _ => (key_identity, None),
    };
    if let Some(occurrence) = recurring {
        identity = occurrence;
    }
    Ok(EntryInfo {
        schema,
        time_tick,
        period,
        resolution,
        supersession,
        supersession_reasons,
        evidence,
        identity,
        legacy_identity,
    })
}

#[derive(Clone, Debug)]
pub(super) struct Account {
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub normal_balance: u8,
    pub is_leaf: bool,
    pub unit_policy: i64,
    pub limit: Option<BalanceLimit>,
    pub created_at: u64,
}
#[derive(Clone, Debug)]
pub(super) struct BalanceLimit {
    pub lower: Option<i128>,
    pub upper: Option<i128>,
    pub period_scoped: bool,
}
#[derive(Clone, Debug)]
struct Period {
    start: i32,
    end: i32,
    kind: u8,
}
#[derive(Default)]
pub(super) struct Schema {
    pub accounts: BTreeMap<u128, Account>,
    calendar: Option<String>,
    periods: BTreeMap<String, Period>,
    native_control_accounts: BTreeSet<u128>,
    native_subledger_codes: BTreeSet<String>,
}

fn account(r: &mut Reader<'_>, recorded_at: u64) -> Result<Account, ReportError> {
    let code = text(r, 64, "account.code")?.to_string();
    let name = text(r, MAX_RECORD_BYTES, "account.name")?.to_string();
    let account_type = r.u8("account.type")?;
    let normal = r.u8("account.normal")?;
    let is_leaf = r.present("account.posting")?;
    let policy = r.i64("account.unit_policy")?;
    if r.present("account.parent")? {
        text(r, 64, "account.parent")?;
    }
    if code.is_empty()
        || !(1..=8).contains(&account_type)
        || normal > 1
        || policy < -2
        || policy > i64::from(u32::MAX)
    {
        return Err(failed(
            "account_metadata",
            "invalid registered account declaration",
        ));
    }
    Ok(Account {
        code,
        name,
        account_type,
        normal_balance: normal,
        is_leaf,
        unit_policy: policy,
        limit: None,
        created_at: recorded_at,
    })
}
fn optional_limit(r: &mut Reader<'_>) -> Result<BalanceLimit, ReportError> {
    let lower = r
        .present("limit.lower")?
        .then(|| r.i128("limit.lower"))
        .transpose()?;
    let upper = r
        .present("limit.upper")?
        .then(|| r.i128("limit.upper"))
        .transpose()?;
    if lower.is_none() && upper.is_none() || matches!((lower, upper), (Some(l), Some(u)) if l > u) {
        return Err(failed("account_metadata", "invalid account balance limit"));
    }
    Ok(BalanceLimit {
        lower,
        upper,
        period_scoped: false,
    })
}
impl Schema {
    pub(super) fn has_historical_periods(&self) -> bool {
        self.periods.values().any(|period| period.kind == 4)
    }

    fn add(&mut self, account: Account, book: &[u8; 16]) -> Result<(), ReportError> {
        let id = crate::ads::account_vid(book, &account.code);
        if self.accounts.insert(id, account).is_some() {
            return Err(failed(
                "account_metadata",
                "an account code is declared more than once",
            ));
        }
        Ok(())
    }
    pub fn apply(
        &mut self,
        kind: u16,
        bytes: &[u8],
        book: &[u8; 16],
        recorded_at: u64,
    ) -> Result<(), ReportError> {
        let mut r = Reader::new(bytes);
        match kind {
            1 => {
                let n = r.count(MAX_ROWS, 20, "chart.accounts")?;
                let mut codes = BTreeSet::new();
                for _ in 0..n {
                    let a = account(&mut r, recorded_at)?;
                    codes.insert(a.code.clone());
                    self.add(a, book)?;
                }
                if r.remaining() != 0 {
                    let n = r.count(codes.len(), 6, "chart.limits")?;
                    let mut limited = BTreeSet::new();
                    for _ in 0..n {
                        let code = text(&mut r, 64, "chart.limit_account")?;
                        if !codes.contains(code) || !limited.insert(code.to_string()) {
                            return Err(failed("account_metadata", "invalid chart limit account"));
                        }
                        let limit = optional_limit(&mut r)?;
                        self.accounts
                            .get_mut(&crate::ads::account_vid(book, code))
                            .ok_or_else(|| failed("account_metadata", "absent limited account"))?
                            .limit = Some(limit);
                    }
                    if r.remaining() != 0 {
                        let n = r.count(limited.len(), 4, "chart.period_limits")?;
                        let mut seen = BTreeSet::new();
                        for _ in 0..n {
                            let code = text(&mut r, 64, "chart.period_limit_account")?;
                            if !limited.contains(code) || !seen.insert(code) {
                                return Err(failed(
                                    "account_metadata",
                                    "invalid period limit account",
                                ));
                            }
                            self.accounts
                                .get_mut(&crate::ads::account_vid(book, code))
                                .and_then(|account| account.limit.as_mut())
                                .ok_or_else(|| failed("account_metadata", "absent period limit"))?
                                .period_scoped = true;
                        }
                    }
                }
            }
            2 => {
                let mut a = account(&mut r, recorded_at)?;
                if r.present("account.limit")? {
                    let mut limit = optional_limit(&mut r)?;
                    let scope = r.u8("limit.scope")?;
                    if scope > 1 {
                        return Err(failed("account_metadata", "unknown limit scope"));
                    }
                    limit.period_scoped = scope == 1;
                    a.limit = Some(limit);
                }
                let opened = r.i32("account.opened")?;
                if r.present("account.closed")? && r.i32("account.closed")? <= opened {
                    return Err(failed("account_metadata", "empty account effectivity"));
                }
                self.add(a, book)?;
            }
            3 | 4 => {
                let code = text(&mut r, 64, "account.code")?;
                if !self
                    .accounts
                    .contains_key(&crate::ads::account_vid(book, code))
                {
                    return Err(failed(
                        "account_metadata",
                        "account lifecycle precedes declaration",
                    ));
                }
                r.i32("account.lifecycle_date")?;
                let id = crate::ads::account_vid(book, code);
                if kind == 4 {
                    let account = self
                        .accounts
                        .get_mut(&id)
                        .ok_or_else(|| failed("account_metadata", "absent promoted account"))?;
                    if !account.is_leaf
                        || account.limit.is_some()
                        || self.native_control_accounts.contains(&id)
                    {
                        return Err(failed(
                            "account_metadata",
                            "account is already a summary, limited, or controls a native subledger",
                        ));
                    }
                    account.is_leaf = false;
                }
                // Native property mutation retires the prior vertex version;
                // both close and promotion advance its created_at sequence.
                self.accounts
                    .get_mut(&id)
                    .ok_or_else(|| failed("account_metadata", "absent lifecycle account"))?
                    .created_at = recorded_at;
            }
            13 => {
                if &r.fixed::<21>("period_creation.domain")? != b"fa:period-creation:v1" {
                    return Err(failed("period_metadata", "unsupported period declaration"));
                }
                let calendar = text(&mut r, 128, "period.calendar")?;
                if calendar.is_empty() || self.calendar.as_deref().is_some_and(|c| c != calendar) {
                    return Err(failed(
                        "period_metadata",
                        "period controls name different calendars",
                    ));
                }
                self.calendar = Some(calendar.into());
                let year = r.i32("period.year")?;
                let n = r.count(19, 4 + 4 + 2 + 1 + 4 + 4 + 1, "period.definitions")?;
                if n == 0 {
                    return Err(failed("period_metadata", "empty period declaration"));
                }
                for _ in 0..n {
                    let code = text(&mut r, 128, "period.code")?.to_string();
                    let fy = r.i32("period.fiscal_year")?;
                    r.u16("period.ordinal")?;
                    let kind = r.u8("period.kind")?;
                    let start = r.i32("period.start")?;
                    let end = r.i32("period.end")?;
                    let state = r.u8("period.state")?;
                    if code.is_empty()
                        || fy != year
                        || kind > 4
                        || start >= end
                        || !matches!(state, 0 | 4)
                        || self
                            .periods
                            .insert(code, Period { start, end, kind })
                            .is_some()
                    {
                        return Err(failed(
                            "period_metadata",
                            "invalid or duplicate period birth",
                        ));
                    }
                }
            }
            15 => {
                if &r.fixed::<{ b"fa:native-subledger:v1".len() }>("native_subledger.format")?
                    != b"fa:native-subledger:v1"
                {
                    return Err(failed(
                        "account_metadata",
                        "unknown native subledger declaration",
                    ));
                }
                let code = text(&mut r, 64, "native_subledger.code")?;
                let name = text(&mut r, 256, "native_subledger.name")?;
                let kind = r.u8("native_subledger.kind")?;
                let id = r.u128("native_subledger.control_account")?;
                if code.is_empty()
                    || name.is_empty()
                    || !matches!(kind, 1 | 2)
                    || !self.native_subledger_codes.insert(code.into())
                    || !self.native_control_accounts.insert(id)
                {
                    return Err(failed(
                        "account_metadata",
                        "invalid or duplicate native subledger declaration",
                    ));
                }
                let account = self.accounts.get_mut(&id).ok_or_else(|| {
                    failed(
                        "account_metadata",
                        "native subledger control account is absent",
                    )
                })?;
                if !account.is_leaf || account.account_type != kind {
                    return Err(failed(
                        "account_metadata",
                        "native subledger requires a correctly typed posting account",
                    ));
                }
                // The native control_of property changes this account's row
                // version even though its rendered name/type remain unchanged.
                account.created_at = recorded_at;
            }
            // Existing REA controls, role/closing/FX declarations,
            // dimension values (17), requirements (18) and closes (19), and
            // Canon rule versions (20) change neither the immutable account
            // labels nor period boundaries.
            5..=12 | 14 | 16..=20 => return Ok(()),
            _ => {
                return Err(failed(
                    "schema_history",
                    format!("schema change {kind} is not supported by this fold version"),
                ));
            }
        }
        r.finish("schema body")?;
        Ok(())
    }
    pub fn selection(
        &self,
        selection: &Selection,
    ) -> Result<(Vec<String>, Option<i32>, bool), ReportError> {
        if self.periods.is_empty() {
            return Err(failed(
                "period_metadata",
                "report requires authenticated period-birth controls",
            ));
        }
        match selection {
            Selection::Statement(_)
            | Selection::OpenItems(_)
            | Selection::ExplainBalance { .. } => Err(failed(
                "report_selector",
                "report selection requires its authenticated registry closure",
            )),
            Selection::AsOf(day) => Ok((
                self.periods
                    .iter()
                    .filter(|(_, p)| p.start <= *day)
                    .map(|(code, _)| code.clone())
                    .collect(),
                Some(*day),
                false,
            )),
            Selection::Periods(codes) | Selection::Activity(codes) => {
                let mut through = i32::MIN;
                for code in codes {
                    let p = self.periods.get(code).ok_or_else(|| {
                        failed(
                            "period_metadata",
                            format!(
                                "period {code} is absent from the authenticated schema history"
                            ),
                        )
                    })?;
                    through = through.max(
                        p.end
                            .checked_sub(1)
                            .ok_or_else(|| failed("period_metadata", "period-end underflow"))?,
                    );
                }
                let activity = matches!(selection, Selection::Activity(_));
                Ok((codes.clone(), (!activity).then_some(through), activity))
            }
        }
    }
    pub fn bounds(&self, codes: &[String]) -> Result<(i32, i32), ReportError> {
        if codes.is_empty() {
            return Err(failed(
                "period_metadata",
                "empty statement period selection",
            ));
        }
        let mut first = i32::MAX;
        let mut last = i32::MIN;
        for code in codes {
            let p = self.periods.get(code).ok_or_else(|| {
                failed(
                    "period_metadata",
                    format!("unknown statement period {code}"),
                )
            })?;
            first = first.min(p.start);
            last = last.max(
                p.end
                    .checked_sub(1)
                    .ok_or_else(|| failed("period_metadata", "period-end underflow"))?,
            );
        }
        Ok((first, last))
    }
    pub fn period_kind(&self, code: &str) -> Result<u8, ReportError> {
        self.periods
            .get(code)
            .map(|period| period.kind)
            .ok_or_else(|| failed("period_metadata", "unknown entry period"))
    }
    pub fn entry_period(
        &self,
        info: &EntryInfo<'_>,
        effective: i32,
    ) -> Result<String, ReportError> {
        if let Some((calendar, code)) = info.period {
            if self.calendar.as_deref() != Some(calendar) {
                return Err(failed(
                    "period_metadata",
                    "entry names an unrelated calendar",
                ));
            }
            let p = self
                .periods
                .get(code)
                .ok_or_else(|| failed("period_metadata", "entry names an absent period"))?;
            if p.start <= effective && effective < p.end {
                return Ok(code.into());
            }
            return Err(failed(
                "period_metadata",
                "entry date is outside its named period",
            ));
        }
        let mut selected = self
            .periods
            .iter()
            .filter(|(_, p)| matches!(p.kind, 0 | 4) && p.start <= effective && effective < p.end);
        let (code, _) = selected
            .next()
            .ok_or_else(|| failed("period_metadata", "entry has no containing normal period"))?;
        if selected.next().is_some() {
            return Err(failed(
                "period_metadata",
                "entry has ambiguous normal periods",
            ));
        }
        Ok(code.clone())
    }
}
const MAX_ROWS: usize = 1 << 20;
