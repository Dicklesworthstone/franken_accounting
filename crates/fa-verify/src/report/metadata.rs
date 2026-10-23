//! Metadata reconstructed from authenticated journal controls, never from
//! producer-supplied account or period projections.

use super::{ReportError, Selection, failed, text};
use crate::codec::Reader;
use crate::envelope::{
    LeafEnvelope, MAX_ENVELOPE_LIST, MAX_RECORD_BYTES, proposal_after_legs, skip_control,
    skip_erasable, skip_origin,
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct EntryInfo<'a> {
    pub schema: Option<(u16, &'a [u8])>,
    pub period: Option<(&'a str, &'a str)>,
    pub resolution: Option<(u128, [u8; 32])>,
    pub supersession: Vec<(u128, [u8; 32], u8)>,
    pub identity: u128,
    /// Before replacement-pair identities were target-derived, the immutable
    /// corrected member used its ordinary key identity. Both encodings name
    /// the same authenticated payload, never an arbitrary producer alias.
    legacy_identity: Option<u128>,
}

impl EntryInfo<'_> {
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
    if r.present("entry.control")? {
        let mut probe = Reader::new(&proposal[proposal.len() - r.remaining()..]);
        if probe.u8("control.tag")? == 1 {
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
        }
        skip_control(&mut r)?;
    }
    let n = r.count(MAX_ENVELOPE_LIST, 36, "entry.unit_totals")?;
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
    for _ in 0..n {
        r.fixed::<65>("evidence")?;
    }
    let n = r.count(MAX_ENVELOPE_LIST, 51, "entry.supersession")?;
    let mut supersession = Vec::with_capacity(n);
    for _ in 0..n {
        let target = r.u128("supersession.target")?;
        let digest = r.fixed("supersession.digest")?;
        let kind = r.u8("supersession.kind")?;
        r.u16("supersession.reason")?;
        supersession.push((target, digest, kind));
    }
    let mut resolution = None;
    if r.present("entry.pending")? {
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
        period,
        resolution,
        supersession,
        identity,
        legacy_identity,
    })
}

#[derive(Clone, Debug)]
pub(super) struct Account {
    pub code: String,
    pub name: String,
    pub account_type: u8,
    pub is_leaf: bool,
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
}

fn account(r: &mut Reader<'_>) -> Result<Account, ReportError> {
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
        is_leaf,
    })
}
fn optional_limit(r: &mut Reader<'_>) -> Result<(), ReportError> {
    if r.present("limit.lower")? {
        r.i128("limit.lower")?;
    }
    if r.present("limit.upper")? {
        r.i128("limit.upper")?;
    }
    Ok(())
}
impl Schema {
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
    pub fn apply(&mut self, kind: u16, bytes: &[u8], book: &[u8; 16]) -> Result<(), ReportError> {
        let mut r = Reader::new(bytes);
        match kind {
            1 => {
                let n = r.count(MAX_ROWS, 20, "chart.accounts")?;
                let mut codes = BTreeSet::new();
                for _ in 0..n {
                    let a = account(&mut r)?;
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
                        optional_limit(&mut r)?;
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
                        }
                    }
                }
            }
            2 => {
                let a = account(&mut r)?;
                if r.present("account.limit")? {
                    optional_limit(&mut r)?;
                    if r.u8("limit.scope")? > 1 {
                        return Err(failed("account_metadata", "unknown limit scope"));
                    }
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
            // Existing REA controls and role/closing/FX/subledger declarations
            // change neither the immutable account labels nor period boundaries.
            5..=12 | 14..=16 => return Ok(()),
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
            Selection::Statement(_) => Err(failed(
                "report_selector",
                "statement columns require their own period selectors",
            )),
        }
    }
    pub fn bounds(&self, codes: &[String]) -> Result<(i32, i32), ReportError> {
        let mut first = i32::MAX;
        let mut last = i32::MIN;
        for code in codes {
            let period = self.periods.get(code).ok_or_else(|| {
                failed(
                    "period_metadata",
                    format!("unknown statement period {code}"),
                )
            })?;
            first = first.min(period.start);
            last = last.max(
                period
                    .end
                    .checked_sub(1)
                    .ok_or_else(|| failed("period_metadata", "statement period end underflow"))?,
            );
        }
        if codes.is_empty() || first > last {
            return Err(failed(
                "period_metadata",
                "empty statement period selection",
            ));
        }
        Ok((first, last))
    }
    pub fn is_closing_period(&self, info: &EntryInfo<'_>, day: i32) -> Result<bool, ReportError> {
        let code = self.entry_period(info, day)?;
        Ok(self
            .periods
            .get(&code)
            .is_some_and(|period| period.kind == 3))
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
