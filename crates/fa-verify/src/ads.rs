//! `fa-verify ads`: an AICPA ADS GL extract (`fa export ads --with-proofs`)
//! checked offline against the complete-prefix bundle produced with it
//! (plan §13.1, §15.6; bead fa-2q91).
//!
//! The bundle proves the journal prefix complete through its signed
//! checkpoint's `through_seq`. The extract's coordinate certificate states
//! the same sequence and its effective-through cutoff. Every proven entry
//! the export selects (posting legs, not a Pending hold, effective on or
//! before the cutoff) must appear in `GL_Detail.txt` with exactly its legs,
//! in order, and no other row may appear. Rows are grouped by `Journal_ID`
//! and matched to proven entries of the same recorded sequence by class,
//! effective date and legs. A row's account is matched by deriving its vid
//! from its code and the book id; unit codes are matched to the legs' unit
//! ids one to one (the codes' names are not authenticated offline). A
//! migration chunk counts exactly when its run makes it visible: a verified
//! migration-aware balance over one of its cells (fa-mv0f) decides that from
//! the run bodies it carries, and its fold reads exactly the visible chunks.
//! A chunk no verified balance covers is refused, never guessed. `Trial_Balance.txt` must then be exactly the
//! refold of those proven rows, so it is proven too. Against a complete
//! prefix, `Chart_of_Accounts.txt` must be exactly the chart the proven
//! entries declare at the sequence (code, name, type, normal balance); one
//! account's scope-index run carries no chart declaration, so its chart is
//! not judged and the report says so (`chart_rows: None`).
//! The optional dimension extension compares every leg's complete ordered
//! kind/value identities to its authenticated proposal. Historical extracts
//! without that extension retain monetary verification but explicitly report
//! `dimension_rows: None`; they cannot establish dimensional attribution.

use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use crate::balance::CLASS_MIGRATION;
use crate::blake3::hash_parts;
use crate::bundle::{BundleError, BundleReport, BundleScope, civil, verify_bundle_observing};
use crate::envelope::{KIND_ENTRY, LeafEnvelope, Leg, proposal_leg_details};

/// `EntryClass::PENDING`: a hold, never exported.
pub const CLASS_PENDING: u16 = 2;
/// The GL_Detail header `fa export ads` writes.
pub const GL_HEADER: &str = "Journal_ID|Journal_Entry_Line_Number|Effective_Date|Recorded_Seq|Entry_Class|GL_Account_Number|Debit_Credit_Indicator|Amount|Transaction_Currency|Unit_Scale|JE_Header_Description|Migrated_From|Line_Description";
const GL_FIELDS: usize = 13;
/// Optional, versioned native dimension identities on every exported leg.
pub const DIMENSION_HEADER: &str = "FA_Dimension_Set_V1";
pub(crate) const DIMENSION_ENCODING: &str = "fa-dimension-ids-v1";
const MAX_DIMENSIONS: usize = 64;
/// The Trial_Balance header `fa export ads` writes.
pub const TB_HEADER: &str =
    "GL_Account_Number|As_Of_Date|Debit_Credit_Indicator|Ending_Balance|Currency|Unit_Scale";

/// What the extract check found, beside the bundle's own report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdsReport {
    pub bundle: BundleReport,
    /// The cutoff and sequence the coordinate certificate states.
    pub effective_through: String,
    pub known_at_seq: Option<u64>,
    /// The one account the extract is scoped to (`fa export ads --account`),
    /// else the whole chart.
    pub account_scope: Option<String>,
    /// GL_Detail entries and rows matched to proven entries.
    pub entries: u64,
    pub rows: u64,
    /// Trial_Balance rows equal to the refold of those rows.
    pub tb_rows: u64,
    /// Chart_of_Accounts rows equal to the chart the proven entries declare:
    /// code, name, type and normal balance. `None` when the bundle proves
    /// one account's run, which carries no chart declaration.
    pub chart_rows: Option<u64>,
    /// Rows whose complete dimension sets match their authenticated native
    /// proposals, including explicit empty sets. Historical extracts without
    /// the versioned extension leave this `None`; monetary equality does not
    /// authenticate omitted dimensions.
    pub dimension_rows: Option<u64>,
    /// Unit code to the unit id its rows matched, one to one.
    pub units: Vec<(String, u32)>,
    /// Every way the extract differs from the proven selection.
    pub failures: Vec<String>,
}

impl AdsReport {
    /// The bundle verified and the extract's stated fields match its selection.
    /// Dimension coverage is separately reported by `dimension_rows`.
    #[must_use]
    pub fn verified(&self) -> bool {
        self.bundle.verified() && self.failures.is_empty()
    }
}

/// `vid(Account) = H("fa:vid:account:v1" ‖ book_id ‖ code)`, each part
/// length-prefixed (u32 LE), the first 16 bytes little-endian.
#[must_use]
pub fn account_vid(book_id: &[u8; 16], code: &str) -> u128 {
    let book_len = 16u32.to_le_bytes();
    let code_len = u32::try_from(code.len()).unwrap_or(u32::MAX).to_le_bytes();
    let digest = hash_parts(
        b"fa:vid:account:v1",
        &[&book_len, book_id, &code_len, code.as_bytes()],
    );
    let mut low = [0u8; 16];
    low.copy_from_slice(&digest[..16]);
    u128::from_le_bytes(low)
}

/// One extract row (a GL_Detail row, or a SAF-T transaction line).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    pub(crate) journal_id: String,
    pub(crate) line: u32,
    pub(crate) date: String,
    pub(crate) seq: u64,
    pub(crate) class: u16,
    pub(crate) account: String,
    pub(crate) debit: bool,
    pub(crate) mantissa: i128,
    pub(crate) unit: String,
    pub(crate) scale: u32,
    pub(crate) dimensions: Option<Vec<(u32, u128)>>,
}

/// One extract entry: its rows in line order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Extracted {
    pub(crate) journal_id: String,
    pub(crate) seq: u64,
    pub(crate) date: String,
    pub(crate) class: u16,
    pub(crate) rows: Vec<Row>,
}

/// One balance as an extract states it (a Trial_Balance row, or a SAF-T
/// balance assertion). `side` is `D` or `C`; `scale` is stated by ADS only
/// (SAF-T states it by the amount's decimals).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StatedBalance {
    pub(crate) line: String,
    pub(crate) account: String,
    pub(crate) as_of: String,
    pub(crate) side: String,
    pub(crate) amount: String,
    pub(crate) unit: String,
    pub(crate) scale: Option<u32>,
}

/// One chart row as an extract states it; `side` is `D` or `C`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StatedAccount {
    pub(crate) line: String,
    pub(crate) code: String,
    pub(crate) name: String,
    pub(crate) account_type: String,
    pub(crate) side: String,
    /// Present only when the extract explicitly carries versioned role metadata.
    pub(crate) roles: Option<Vec<String>>,
}

/// What an extract states, read by its own format's reader: its coordinate,
/// entries, balances and chart. A part that does not read is its error.
pub(crate) struct Stated {
    pub(crate) effective_through: String,
    pub(crate) known_at_seq: Option<u64>,
    pub(crate) entry_count: Option<u64>,
    pub(crate) account_scope: Option<String>,
    pub(crate) dimension_encoding: bool,
    pub(crate) entries: Result<Vec<Extracted>, String>,
    pub(crate) balances: Result<Vec<StatedBalance>, String>,
    pub(crate) chart: Result<Vec<StatedAccount>, String>,
}

/// The names a format gives its parts, for failure messages.
pub(crate) struct Parts {
    /// `ADS` or `SAF-T`.
    pub(crate) format: &'static str,
    pub(crate) coordinate: &'static str,
    pub(crate) entries: &'static str,
    pub(crate) entry: &'static str,
    pub(crate) balances: &'static str,
    pub(crate) chart: &'static str,
}

const ADS_PARTS: Parts = Parts {
    format: "ADS",
    coordinate: "the certificate",
    entries: "GL_Detail",
    entry: "GL_Detail entry",
    balances: "Trial_Balance",
    chart: "Chart_of_Accounts",
};

/// One proven entry the export selects.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Proven {
    class: u16,
    date: String,
    legs: Vec<Leg>,
    dimensions: Vec<Vec<(u32, u128)>>,
}

/// Independently decode the bounded dimension extension. The native proposal
/// authenticates identities, not display names: kind IDs are canonical u32
/// decimals, value IDs exactly 32 lowercase hexadecimal digits, and kind IDs
/// strictly increase. Empty text explicitly represents an untagged leg.
pub(crate) fn dimension_set(text: &str) -> Result<Vec<(u32, u128)>, String> {
    let bad = || {
        "a dimension set requires at most 64 increasing canonical u32 kind IDs and 32 lowercase hexadecimal value IDs".to_string()
    };
    if text.len() > MAX_DIMENSIONS * 44 {
        return Err(bad());
    }
    if text.is_empty() {
        return Ok(Vec::new());
    }
    let mut parsed: Vec<(u32, u128)> = Vec::new();
    for item in text.split(';') {
        if parsed.len() == MAX_DIMENSIONS {
            return Err(bad());
        }
        let (kind, value) = item.split_once(':').ok_or_else(bad)?;
        if kind.is_empty()
            || (kind.len() > 1 && kind.starts_with('0'))
            || !kind.bytes().all(|byte| byte.is_ascii_digit())
            || value.len() != 32
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(bad());
        }
        let mut id = 0u32;
        for digit in kind.bytes() {
            id = id
                .checked_mul(10)
                .and_then(|n| n.checked_add(u32::from(digit - b'0')))
                .ok_or_else(bad)?;
        }
        if parsed.last().is_some_and(|previous| previous.0 >= id) {
            return Err(bad());
        }
        let value = u128::from_str_radix(value, 16).map_err(|_| bad())?;
        parsed.push((id, value));
    }
    Ok(parsed)
}

/// `value` at `scale` decimal places as an exact mantissa: digits, then a
/// point and exactly `scale` digits when `scale > 0`.
pub(crate) fn exact(value: &str, scale: u32) -> Option<i128> {
    let (whole, fraction) = match value.split_once('.') {
        Some((w, f)) if scale > 0 && f.len() == usize::try_from(scale).ok()? => (w, f),
        None if scale == 0 => (value, ""),
        _ => return None,
    };
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let mut m: i128 = 0;
    for b in whole.bytes().chain(fraction.bytes()) {
        m = m.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
    }
    Some(m)
}

// Independent std-only reader for the v3 text law. Do not import fa-formats:
// the offline verifier must not share its writer or parser implementation.
fn decode_field(field: &str) -> Result<String, String> {
    let mut decoded = String::new();
    let mut input = field.chars();
    while let Some(c) = input.next() {
        if c != '\\' {
            if c.is_control() {
                return Err("unescaped control character in ADS v3 text".into());
            }
            decoded.push(c);
            continue;
        }
        let c = match input.next() {
            Some('\\') => '\\',
            Some('p') => '|',
            Some('n') => '\n',
            Some('r') => '\r',
            Some('u') => {
                let digits: String = input.by_ref().take(4).collect();
                if digits.len() != 4
                    || !digits
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err("invalid ADS v3 control escape".into());
                }
                let scalar =
                    u32::from_str_radix(&digits, 16).map_err(|_| "invalid ADS v3 scalar")?;
                let control = char::from_u32(scalar).ok_or("invalid ADS v3 scalar")?;
                if !control.is_control() || matches!(control, '\n' | '\r') {
                    return Err("noncanonical ADS v3 control escape".into());
                }
                control
            }
            _ => return Err("unknown or incomplete ADS v3 text escape".into()),
        };
        decoded.push(c);
    }
    Ok(decoded)
}

fn fields(line: &str, escaped: bool, gl: bool) -> Result<Vec<String>, String> {
    line.split('|')
        .enumerate()
        .map(|(i, s)| {
            if escaped && gl && matches!(i, 11 | 12) && s == "\\N" {
                Ok(String::new())
            } else if escaped {
                decode_field(s)
            } else {
                Ok(s.into())
            }
        })
        .collect()
}

fn parse_row(line: &str, number: usize, escaped: bool, dimensions: bool) -> Result<Row, String> {
    let decoded = fields(line, escaped, true)?;
    let fields: Vec<&str> = decoded.iter().map(String::as_str).collect();
    let expected = GL_FIELDS + usize::from(dimensions);
    if fields.len() != expected {
        return Err(format!(
            "GL_Detail line {number} has {} fields, not {expected} (a description holding a line break makes a row unreadable)",
            fields.len()
        ));
    }
    let bad = |what: &str| format!("GL_Detail line {number}: {what} `{}`", fields[0]);
    let scale: u32 = fields[9].parse().map_err(|_| bad("Unit_Scale"))?;
    Ok(Row {
        journal_id: fields[0].to_string(),
        line: fields[1]
            .parse()
            .map_err(|_| bad("Journal_Entry_Line_Number"))?,
        date: fields[2].to_string(),
        seq: fields[3].parse().map_err(|_| bad("Recorded_Seq"))?,
        class: fields[4].parse().map_err(|_| bad("Entry_Class"))?,
        account: fields[5].to_string(),
        debit: match fields[6] {
            "D" => true,
            "C" => false,
            _ => return Err(bad("Debit_Credit_Indicator")),
        },
        mantissa: exact(fields[7], scale).ok_or_else(|| bad("Amount at its Unit_Scale"))?,
        unit: fields[8].to_string(),
        scale,
        dimensions: dimensions
            .then(|| dimension_set(fields[GL_FIELDS]))
            .transpose()?,
    })
}

/// GL_Detail as entries, rows grouped by `Journal_ID` in first-seen order,
/// each numbered 1.. in order and agreeing on sequence, date and class.
fn extracted(gl_detail: &str, escaped: bool, dimensions: bool) -> Result<Vec<Extracted>, String> {
    let mut lines = gl_detail.split('\n');
    let expected = if dimensions {
        format!("{GL_HEADER}|{DIMENSION_HEADER}")
    } else {
        GL_HEADER.to_string()
    };
    if lines.next() != Some(expected.as_str()) {
        return Err("GL_Detail does not start with the ADS GL header".to_string());
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_id: BTreeMap<String, Extracted> = BTreeMap::new();
    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let row = parse_row(line, i.saturating_add(2), escaped, dimensions)?;
        let entry = by_id.entry(row.journal_id.clone()).or_insert_with(|| {
            order.push(row.journal_id.clone());
            Extracted {
                journal_id: row.journal_id.clone(),
                seq: row.seq,
                date: row.date.clone(),
                class: row.class,
                rows: Vec::new(),
            }
        });
        let next = u32::try_from(entry.rows.len())
            .ok()
            .and_then(|n| n.checked_add(1));
        if (entry.seq, entry.date.as_str(), entry.class) != (row.seq, row.date.as_str(), row.class)
            || next != Some(row.line)
        {
            return Err(format!(
                "GL_Detail entry {}: its rows disagree on sequence, date or class, or are not numbered 1.. in order",
                row.journal_id
            ));
        }
        entry.rows.push(row);
    }
    Ok(order
        .into_iter()
        .filter_map(|id| by_id.remove(&id))
        .collect())
}

/// Lowercase hex of UTF-8 bytes (the v3 certificate's `*_utf8_hex` values).
fn utf8_hex(hex: &str) -> Option<String> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| {
            let pair = hex.get(i..i + 2)?;
            if !pair
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            {
                return None;
            }
            u8::from_str_radix(pair, 16).ok()
        })
        .collect::<Option<Vec<u8>>>()?;
    String::from_utf8(bytes).ok()
}

/// Read `key = value` (a TOML string or integer) from the certificate.
fn field<'a>(certificate: &'a str, key: &str) -> Option<&'a str> {
    certificate.lines().find_map(|line| {
        let (k, v) = line.split_once('=')?;
        (k.trim() == key).then(|| v.trim().trim_matches('"'))
    })
}

/// The optional extension marker must be unique and exact. In particular,
/// removing it cannot leave a 14-column export silently treated as legacy.
fn dimension_encoding(certificate: &str) -> Result<bool, String> {
    let mut found = false;
    for line in certificate.lines() {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim() != "dimension_encoding" {
            continue;
        }
        if found || value.trim() != format!("\"{DIMENSION_ENCODING}\"") {
            return Err("the certificate's dimension_encoding is duplicated or unsupported".into());
        }
        found = true;
    }
    Ok(found)
}

/// Units consistent so far: code to id and back, one to one.
#[derive(Default)]
struct Units {
    by_code: BTreeMap<String, u32>,
    by_id: BTreeMap<u32, String>,
}

impl Units {
    fn admits(&self, code: &str, id: u32) -> bool {
        self.by_code.get(code).is_none_or(|i| *i == id)
            && self.by_id.get(&id).is_none_or(|c| c == code)
    }
}

/// Whether `extract` is exactly `proven`: same class and date, and legs in
/// order with each row's account, side, amount and (consistent) unit.
#[cfg(test)]
fn same(extract: &Extracted, proven: &Proven, book: &[u8; 16], units: &Units) -> bool {
    extract.class == proven.class
        && extract.date == proven.date
        && extract.rows.len() == proven.legs.len()
        && extract
            .rows
            .iter()
            .zip(&proven.legs)
            .enumerate()
            .all(|(i, (row, leg))| {
                account_vid(book, &row.account) == leg.account
                    && row.debit == leg.debit
                    && row.mantissa == leg.mantissa
                    && units.admits(&row.unit, leg.unit)
                    && row
                        .dimensions
                        .as_ref()
                        .is_none_or(|dimensions| proven.dimensions.get(i) == Some(dimensions))
            })
}

/// Immutable matching fields. Units remain separate because their display
/// codes are inferred from earlier matches, in extract order. Dimensions
/// have a separate index so wildcard queries cannot disable exact lookups.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct MatchKey {
    seq: u64,
    class: u16,
    date: String,
    legs: Vec<MatchLeg>,
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct MatchLeg {
    account: u128,
    debit: bool,
    mantissa: i128,
}

/// The observer counts actual matching work in the scaling tests. The
/// production caller supplies a no-op, with no retained counters or state.
#[derive(Clone, Copy)]
enum MatchVisit {
    AccountHash,
    UnitGroup,
    Candidate,
    DimensionIndexRow,
    UnitIndexLeg,
}

// Inverted memberships use live head ordinals, not unit-vector ordering:
// a very common known unit must still stop at its first compatible group.
type UnitVectors = BTreeMap<usize, Rc<[u32]>>;
type UnitIndex = BTreeMap<(usize, u32), UnitVectors>;

/// One immutable signature's candidates, grouped by their ordered unit IDs.
/// Queues retain original record ordinals; their heads are also ordered by
/// ordinal so unresolved unit codes never change the earliest-match rule.
#[derive(Default)]
struct MatchCandidates {
    by_units: BTreeMap<Rc<[u32]>, VecDeque<usize>>,
    by_first: BTreeMap<usize, Rc<[u32]>>,
    /// Built only when a query knows some, but not all, of its unit codes.
    /// Shared vectors keep this linear in group legs, without copying a
    /// whole L-leg vector into each of its L inverted-index memberships.
    by_position: Option<UnitIndex>,
}

impl MatchCandidates {
    fn push(&mut self, units: Rc<[u32]>, index: usize) {
        let queue = match self.by_units.entry(Rc::clone(&units)) {
            std::collections::btree_map::Entry::Occupied(entry) => entry.into_mut(),
            std::collections::btree_map::Entry::Vacant(entry) => {
                self.by_first.insert(index, Rc::clone(&units));
                if let Some(by_position) = &mut self.by_position {
                    for (position, &unit) in units.iter().enumerate() {
                        by_position
                            .entry((position, unit))
                            .or_default()
                            .insert(index, Rc::clone(&units));
                    }
                }
                entry.insert(VecDeque::new())
            }
        };
        queue.push_back(index);
    }

    fn first_in(
        queue: &VecDeque<usize>,
        records: &[Option<(u64, Proven)>],
        extract: &Extracted,
        check_dimensions: bool,
        visit: &mut impl FnMut(MatchVisit),
    ) -> Option<usize> {
        for &index in queue {
            visit(MatchVisit::Candidate);
            let Some((_, proven)) = records.get(index).and_then(Option::as_ref) else {
                continue;
            };
            if !check_dimensions
                || extract.rows.iter().enumerate().all(|(i, row)| {
                    row.dimensions
                        .as_ref()
                        .is_none_or(|dimensions| proven.dimensions.get(i) == Some(dimensions))
                })
            {
                return Some(index);
            }
        }
        None
    }

    fn first_for(
        &self,
        ids: &Rc<[u32]>,
        extract: &Extracted,
        units: &Units,
        records: &[Option<(u64, Proven)>],
        check_dimensions: bool,
        visit: &mut impl FnMut(MatchVisit),
    ) -> Option<usize> {
        visit(MatchVisit::UnitGroup);
        if !extract
            .rows
            .iter()
            .zip(ids.iter())
            .all(|(row, id)| units.admits(&row.unit, *id))
        {
            return None;
        }
        Self::first_in(
            self.by_units.get(ids.as_ref())?,
            records,
            extract,
            check_dimensions,
            visit,
        )
    }

    fn select(
        &mut self,
        extract: &Extracted,
        units: &Units,
        records: &[Option<(u64, Proven)>],
        check_dimensions: bool,
        visit: &mut impl FnMut(MatchVisit),
    ) -> Option<(usize, Rc<[u32]>)> {
        let known: Option<Vec<_>> = extract
            .rows
            .iter()
            .map(|row| units.by_code.get(&row.unit).copied())
            .collect();
        if let Some(ids) = known {
            let (shared, _) = self.by_units.get_key_value(ids.as_slice())?;
            return self
                .first_for(shared, extract, units, records, check_dimensions, visit)
                .map(|index| (index, Rc::clone(shared)));
        }

        let mut constraints = Vec::new();
        for (position, row) in extract.rows.iter().enumerate() {
            if let Some(&id) = units.by_code.get(&row.unit) {
                if !units.admits(&row.unit, id) {
                    return None;
                }
                constraints.push((position, id));
            }
        }
        if !constraints.is_empty() && self.by_units.len() > 1 {
            if self.by_position.is_none() {
                let mut by_position: UnitIndex = BTreeMap::new();
                for (ids, queue) in &self.by_units {
                    let Some(&head) = queue.front() else {
                        continue;
                    };
                    for (position, &id) in ids.iter().enumerate() {
                        visit(MatchVisit::UnitIndexLeg);
                        by_position
                            .entry((position, id))
                            .or_default()
                            .insert(head, Rc::clone(ids));
                    }
                }
                self.by_position = Some(by_position);
            }
            let by_position = self.by_position.as_ref()?;
            let mut eligible: Option<&UnitVectors> = None;
            for constraint in &constraints {
                let matching = by_position.get(constraint)?;
                if eligible.is_none_or(|previous| matching.len() < previous.len()) {
                    eligible = Some(matching);
                }
            }
            let mut first: Option<(usize, Rc<[u32]>)> = None;
            for (&head, ids) in eligible? {
                if first.as_ref().is_some_and(|(index, _)| *index <= head) {
                    break;
                }
                if let Some(index) =
                    self.first_for(ids, extract, units, records, check_dimensions, visit)
                    && first.as_ref().is_none_or(|(earlier, _)| index < *earlier)
                {
                    first = Some((index, Rc::clone(ids)));
                }
            }
            return first;
        }

        // Unbound codes can match several unit vectors. Search group heads
        // in original order, stopping as soon as no earlier match remains.
        // Ambiguous vectors can still require multiple group probes; this
        // is deliberately not a universal logarithmic matching claim.
        let mut first: Option<(usize, Rc<[u32]>)> = None;
        for (&head, ids) in &self.by_first {
            if first.as_ref().is_some_and(|(index, _)| *index <= head) {
                break;
            }
            if let Some(index) =
                self.first_for(ids, extract, units, records, check_dimensions, visit)
                && first.as_ref().is_none_or(|(earlier, _)| index < *earlier)
            {
                first = Some((index, Rc::clone(ids)));
            }
        }
        first
    }

    fn consumed(&mut self, ids: &Rc<[u32]>, records: &[Option<(u64, Proven)>]) {
        let Some(queue) = self.by_units.get_mut(ids.as_ref()) else {
            return;
        };
        let before = queue.front().copied();
        // A mixed optional-dimension match can consume an interior record.
        // Keep its tombstone until it reaches the front, avoiding all vector
        // shifts. Each record is popped at most once during the whole match.
        while queue
            .front()
            .is_some_and(|index| records.get(*index).and_then(Option::as_ref).is_none())
        {
            queue.pop_front();
        }
        let after = queue.front().copied();
        if before != after {
            if let Some(before) = before {
                self.by_first.remove(&before);
            }
            if let Some(after) = after {
                self.by_first.insert(after, Rc::clone(ids));
            } else {
                self.by_units.remove(ids.as_ref());
            }
            if let Some(by_position) = &mut self.by_position {
                for (position, &id) in ids.iter().enumerate() {
                    let key = (position, id);
                    if let Some(groups) = by_position.get_mut(&key) {
                        if let Some(before) = before {
                            groups.remove(&before);
                        }
                        if let Some(after) = after {
                            groups.insert(after, Rc::clone(ids));
                        }
                        if groups.is_empty() {
                            by_position.remove(&key);
                        }
                    }
                }
            }
        }
    }
}

type MatchDimensions = Vec<Option<Vec<(u32, u128)>>>;

fn match_dimensions(proven: &Proven) -> MatchDimensions {
    (0..proven.legs.len())
        .map(|i| proven.dimensions.get(i).cloned())
        .collect()
}

/// Monetary candidates plus a lazily built exact-dimension index. Historical
/// rows use `all`; complete dimension rows use their own bucket even when
/// other extract rows omit dimensions. Both indexes share stable record
/// slots and retire consumed records together.
#[derive(Default)]
struct MatchBucket {
    all: MatchCandidates,
    by_dimensions: Option<BTreeMap<MatchDimensions, MatchCandidates>>,
}

impl MatchBucket {
    fn select(
        &mut self,
        extract: &Extracted,
        units: &Units,
        records: &[Option<(u64, Proven)>],
        visit: &mut impl FnMut(MatchVisit),
    ) -> Option<(usize, Rc<[u32]>)> {
        let check_dimensions = extract.rows.iter().any(|row| row.dimensions.is_some());
        if check_dimensions && extract.rows.iter().all(|row| row.dimensions.is_some()) {
            if self.by_dimensions.is_none() {
                let mut indexed: BTreeMap<MatchDimensions, MatchCandidates> = BTreeMap::new();
                for (ids, queue) in &self.all.by_units {
                    for &index in queue {
                        visit(MatchVisit::DimensionIndexRow);
                        if let Some((_, proven)) = records.get(index).and_then(Option::as_ref) {
                            indexed
                                .entry(match_dimensions(proven))
                                .or_default()
                                .push(Rc::clone(ids), index);
                        }
                    }
                }
                self.by_dimensions = Some(indexed);
            }
            let dimensions: MatchDimensions = extract
                .rows
                .iter()
                .map(|row| row.dimensions.clone())
                .collect();
            return self
                .by_dimensions
                .as_mut()?
                .get_mut(&dimensions)?
                .select(extract, units, records, false, visit);
        }
        // Truly partial per-row dimensions need the remaining predicates
        // checked, without affecting full or wholly omitted queries.
        self.all
            .select(extract, units, records, check_dimensions, visit)
    }

    fn consumed(&mut self, ids: &Rc<[u32]>, matched: &Proven, records: &[Option<(u64, Proven)>]) {
        self.all.consumed(ids, records);
        if let Some(indexed) = &mut self.by_dimensions {
            let key = match_dimensions(matched);
            if let Some(candidates) = indexed.get_mut(&key) {
                candidates.consumed(ids, records);
                if candidates.by_units.is_empty() {
                    indexed.remove(&key);
                }
            }
        }
    }
}

/// Indexed counterpart of the literal first-compatible-record scan. Stable
/// slots preserve missing-record diagnostics in sequence and source order.
struct ProvenMatcher {
    book: [u8; 16],
    accounts: BTreeMap<String, u128>,
    records: Vec<Option<(u64, Proven)>>,
    candidates: BTreeMap<MatchKey, MatchBucket>,
}

impl ProvenMatcher {
    /// `proven` arrives in recorded-sequence and within-sequence order.
    fn new(proven: impl IntoIterator<Item = (u64, Proven)>, book: [u8; 16]) -> Self {
        let mut matcher = Self {
            book,
            accounts: BTreeMap::new(),
            records: Vec::new(),
            candidates: BTreeMap::new(),
        };
        for (seq, proven) in proven {
            let key = MatchKey {
                seq,
                class: proven.class,
                date: proven.date.clone(),
                legs: proven
                    .legs
                    .iter()
                    .map(|leg| MatchLeg {
                        account: leg.account,
                        debit: leg.debit,
                        mantissa: leg.mantissa,
                    })
                    .collect(),
            };
            let units = proven.legs.iter().map(|leg| leg.unit).collect();
            let index = matcher.records.len();
            matcher.records.push(Some((seq, proven)));
            matcher
                .candidates
                .entry(key)
                .or_default()
                .all
                .push(units, index);
        }
        matcher
    }

    fn take(
        &mut self,
        extract: &Extracted,
        units: &Units,
        mut visit: impl FnMut(MatchVisit),
    ) -> Option<Proven> {
        let key = MatchKey {
            seq: extract.seq,
            class: extract.class,
            date: extract.date.clone(),
            legs: extract
                .rows
                .iter()
                .map(|row| {
                    let account = if let Some(account) = self.accounts.get(&row.account) {
                        *account
                    } else {
                        visit(MatchVisit::AccountHash);
                        let account = account_vid(&self.book, &row.account);
                        self.accounts.insert(row.account.clone(), account);
                        account
                    };
                    MatchLeg {
                        account,
                        debit: row.debit,
                        mantissa: row.mantissa,
                    }
                })
                .collect(),
        };
        let candidates = self.candidates.get_mut(&key)?;
        let (index, ids) = candidates.select(extract, units, &self.records, &mut visit)?;
        let (_, matched) = self.records.get_mut(index)?.take()?;
        candidates.consumed(&ids, &matched, &self.records);
        if candidates.all.by_units.is_empty() {
            self.candidates.remove(&key);
        }
        Some(matched)
    }

    fn remaining(&self) -> impl Iterator<Item = (u64, &Proven)> {
        self.records
            .iter()
            .filter_map(|record| record.as_ref().map(|(seq, proven)| (*seq, proven)))
    }
}

/// The records a verified bundle authenticates: each record's leaf index,
/// envelope, the legs it rebuilds and its proposal bytes.
pub(crate) type Records = Vec<(u64, LeafEnvelope, Vec<Leg>, Vec<u8>)>;

/// What a verified bundle authenticates: its records, and its balances, each
/// with the leaves its fold read. A migration-aware balance proof decides
/// each migration chunk of its cell from the run bodies it carries, and reads
/// exactly the visible ones.
pub(crate) struct Authenticated {
    pub(crate) records: Records,
    pub(crate) balances: Vec<crate::balance::Balance>,
}

/// Verify the bundle and keep what it authenticates.
pub(crate) fn prove(
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    receipt: Option<&[u8]>,
) -> Result<(crate::bundle::BundleReport, Authenticated), BundleError> {
    let mut records: Records = Vec::new();
    let mut balances = Vec::new();
    let report = verify_bundle_observing(
        bundle,
        trusted_keys,
        receipt,
        |_, balance| balances.push(balance.clone()),
        |leaf, envelope, legs, proposal| {
            records.push((leaf, envelope.clone(), legs.to_vec(), proposal.to_vec()));
        },
    )?;
    Ok((report, Authenticated { records, balances }))
}

impl AdsReport {
    /// The bundle's report, before any extract is judged against it.
    pub(crate) fn new(
        bundle: crate::bundle::BundleReport,
        effective_through: String,
        known_at_seq: Option<u64>,
    ) -> Self {
        Self {
            bundle,
            effective_through,
            known_at_seq,
            account_scope: None,
            entries: 0,
            rows: 0,
            tb_rows: 0,
            chart_rows: None,
            dimension_rows: None,
            units: Vec::new(),
            failures: Vec::new(),
        }
    }
}

/// Verify the bundle, then the extract against the entries it proves. The
/// bundle's own failure is reported, never masked; the extract is judged
/// only against a verified complete-prefix bundle.
pub fn verify_ads(
    certificate: &str,
    chart_of_accounts: &str,
    gl_detail: &str,
    trial_balance: &str,
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    receipt: Option<&[u8]>,
) -> Result<AdsReport, BundleError> {
    let (report, authenticated) = prove(bundle, trusted_keys, receipt)?;
    let mut out = AdsReport::new(
        report,
        field(certificate, "effective_through")
            .unwrap_or_default()
            .to_string(),
        field(certificate, "known_at_seq").and_then(|v| v.parse().ok()),
    );
    if !out.bundle.verified() {
        out.failures
            .push("the bundle did not verify, so GL_Detail was not judged against it".into());
        return Ok(out);
    }
    let escaped = match escaped_format(certificate) {
        Ok(escaped) => escaped,
        Err(why) => {
            out.failures.push(why);
            return Ok(out);
        }
    };
    // One account's extract names its account; the whole chart names none.
    let stated = if escaped {
        field(certificate, "account_scope_utf8_hex").map(|hex| utf8_hex(hex).ok_or(()))
    } else {
        field(certificate, "account_scope").map(|code| Ok(code.to_string()))
    };
    let scoped = match stated {
        None => None,
        Some(Ok(code)) => Some(code),
        Some(Err(())) => {
            out.failures
                .push("the certificate's account_scope is not hex UTF-8".into());
            return Ok(out);
        }
    };
    let dimensions = match dimension_encoding(certificate) {
        Ok(dimensions) => dimensions,
        Err(why) => {
            out.failures.push(why);
            return Ok(out);
        }
    };
    let stated = Stated {
        effective_through: out.effective_through.clone(),
        known_at_seq: out.known_at_seq,
        entry_count: field(certificate, "entry_count").and_then(|v| v.parse().ok()),
        account_scope: scoped,
        dimension_encoding: dimensions,
        entries: extracted(gl_detail, escaped, dimensions),
        balances: ads_balances(trial_balance, escaped),
        chart: ads_chart(chart_of_accounts, escaped),
    };
    Ok(judge(out, authenticated, stated, &ADS_PARTS))
}

fn escaped_format(certificate: &str) -> Result<bool, String> {
    match field(certificate, "format") {
        // v4 distinguishes a Trial_Balance derived from GL_Detail from
        // original source assertions. Its escaped text law is v3's, and
        // either profile must still refold exactly from authenticated GL.
        Some("aicpa_ads_gl_v3" | "aicpa_ads_gl_v4") => Ok(true),
        Some("aicpa_ads_gl_v2") | None => Ok(false),
        Some(other) => Err(format!("unsupported ADS format version {other:?}")),
    }
}

/// Judge what an extract states against the records a verified bundle
/// authenticates (the core `fa-verify ads` and `fa-verify saft` share):
/// the coordinate is the checkpoint's; the bundle proves the extract's scope
/// complete; the entries are exactly the proven entries the export selects;
/// the balances are exactly their refold; and, against a complete prefix,
/// the chart is exactly the one the proven entries declare.
pub(crate) fn judge(
    mut out: AdsReport,
    authenticated: Authenticated,
    stated: Stated,
    parts: &Parts,
) -> AdsReport {
    let Authenticated { records, balances } = authenticated;
    let scoped = stated.account_scope;
    out.account_scope.clone_from(&scoped);
    let manifest = out.bundle.manifest.clone();
    if stated.known_at_seq != Some(manifest.through_seq) {
        out.failures.push(format!(
            "{}'s known_at_seq ({}) is not the checkpoint's through_seq ({})",
            parts.coordinate,
            stated
                .known_at_seq
                .map_or_else(|| "absent".to_string(), |s| s.to_string()),
            manifest.through_seq
        ));
        return out;
    }
    let cutoff = stated.effective_through.clone();
    if cutoff.len() != 10 {
        out.failures.push(format!(
            "{} states no effective_through date",
            parts.coordinate
        ));
        return out;
    }
    // The whole chart needs a complete prefix. One account's extract needs
    // the prefix or that account's scope-index run over every effective
    // day through the cutoff (ScopeIndexComplete).
    let account = scoped
        .as_deref()
        .map(|code| account_vid(&manifest.book_id, code));
    let complete = match (&manifest.scope, account) {
        (BundleScope::Prefix, _) => true,
        (BundleScope::Account(claim), Some(vid)) => {
            claim.account == vid && claim.from == i32::MIN && civil(claim.to) == cutoff
        }
        _ => false,
    };
    if !complete {
        out.failures.push(match &scoped {
            None => format!(
                "the bundle proves a narrower scope; a whole-chart {} extract is judged against a complete-prefix bundle",
                parts.format
            ),
            Some(code) => format!(
                "the bundle proves neither the complete prefix nor account {code}'s entries over every effective day through {cutoff}"
            ),
        });
        return out;
    }
    // A complete prefix carries the chart's declarations, so
    // Chart_of_Accounts is judged against them. One account's run carries
    // none: its chart is then not judged, and the report says so.
    let declared = if matches!(manifest.scope, BundleScope::Prefix) {
        match crate::report::declared_chart(
            records.iter().map(|(_, e, _, p)| (e, p.as_slice())),
            &manifest.book_id,
            manifest.through_seq,
        ) {
            Ok(chart) => Some(chart),
            Err(why) => {
                out.failures.push(format!(
                    "the proven chart declarations do not decode: {why}"
                ));
                return out;
            }
        }
    } else {
        None
    };
    // The proven entries the export selects, by recorded sequence.
    let mut proven: BTreeMap<u64, Vec<Proven>> = BTreeMap::new();
    let mut migration_visibility = None;
    for (leaf, envelope, legs, proposal) in records {
        let Some(day) = envelope.effective_day else {
            continue;
        };
        let date = civil(day);
        if envelope.kind != KIND_ENTRY
            || envelope.class == CLASS_PENDING
            || legs.is_empty()
            || date > cutoff
            || account.is_some_and(|vid| legs.iter().all(|leg| leg.account != vid))
        {
            continue;
        }
        if envelope.class == CLASS_MIGRATION {
            let visibility = migration_visibility.get_or_insert_with(|| {
                MigrationVisibility::new(
                    balances
                        .iter()
                        .map(|balance| (&balance.claim, balance.contributing.as_slice())),
                )
            });
            match visibility.chunk_visibility(leaf, day, &legs) {
                Some(true) => {}
                // Its run hides it: the export selects it no more than the
                // fold does.
                Some(false) => continue,
                // An account's scope-index run alone does not prove the
                // run's lifecycle. Its separately verified balance witnesses
                // must cover the migration cells even when the run hides them.
                None if account.is_some() && !matches!(manifest.scope, BundleScope::Prefix) => {
                    out.failures.push(format!(
                        "a migration chunk recorded at {} is in this account's scope, but no migration-aware balance over this account's cells proves whether its run makes it visible; regenerate the {} extract with --with-proofs so its bundle carries the required visibility witnesses",
                        envelope.commit_seq, parts.format
                    ));
                    continue;
                }
                None => {
                    out.failures.push(format!(
                        "a migration chunk recorded at {} is in scope, and no verified balance over its cells proves whether its run makes it visible",
                        envelope.commit_seq
                    ));
                    continue;
                }
            }
        }
        let details = match proposal_leg_details(&proposal) {
            Ok(details) if details.len() == legs.len() => details,
            Ok(_) => {
                out.failures.push(
                    "the authenticated proposal's dimension and monetary leg counts differ".into(),
                );
                return out;
            }
            Err(why) => {
                out.failures.push(format!(
                    "the authenticated proposal's leg details do not decode: {why}"
                ));
                return out;
            }
        };
        proven.entry(envelope.commit_seq).or_default().push(Proven {
            class: envelope.class,
            date,
            legs,
            dimensions: details
                .into_iter()
                .map(|detail| detail.dimensions)
                .collect(),
        });
    }
    // Visibility witnesses have served their purpose. Release them before
    // building the entry matcher, which also has linear auxiliary storage.
    drop(migration_visibility);
    drop(balances);
    let extract = match stated.entries {
        Ok(extract) => extract,
        Err(why) => {
            out.failures.push(why);
            return out;
        }
    };
    let mut proven = ProvenMatcher::new(
        proven
            .into_iter()
            .flat_map(|(seq, entries)| entries.into_iter().map(move |entry| (seq, entry))),
        manifest.book_id,
    );
    let mut units = Units::default();
    for entry in &extract {
        match proven.take(entry, &units, |_| {}) {
            Some(matched) => {
                for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                    units.by_code.insert(row.unit.clone(), leg.unit);
                    units.by_id.insert(leg.unit, row.unit.clone());
                }
                out.entries = out.entries.saturating_add(1);
                out.rows = out
                    .rows
                    .saturating_add(u64::try_from(entry.rows.len()).unwrap_or(u64::MAX));
            }
            None => out.failures.push(format!(
                "{} {} (recorded at {}) is no proven entry selected through {cutoff}",
                parts.entry, entry.journal_id, entry.seq
            )),
        }
    }
    for (seq, p) in proven.remaining() {
        out.failures.push(format!(
            "a proven entry recorded at {seq} (effective {}, {} legs) is missing from {}",
            p.date,
            p.legs.len(),
            parts.entries
        ));
    }
    if out.failures.is_empty() && stated.entry_count != Some(out.entries) {
        out.failures.push(format!(
            "{}'s entry_count ({}) is not the {} entries {} holds",
            parts.coordinate,
            stated
                .entry_count
                .map_or_else(|| "absent".to_string(), |c| c.to_string()),
            out.entries,
            parts.entries
        ));
    }
    if out.failures.is_empty() {
        match stated.balances.and_then(|balances| {
            balance_rows(&balances, &extract, &cutoff, scoped.as_deref(), parts)
        }) {
            Ok(rows) => out.tb_rows = rows,
            Err(why) => out.failures.push(why),
        }
    }
    if out.failures.is_empty()
        && let Some(declared) = &declared
    {
        match stated
            .chart
            .and_then(|chart| chart_matches(&chart, declared, &extract, scoped.as_deref(), parts))
        {
            Ok(rows) => out.chart_rows = Some(rows),
            Err(why) => out.failures.push(why),
        }
    }
    out.units = units.by_code.into_iter().collect();
    if out.failures.is_empty() && stated.dimension_encoding {
        out.dimension_rows = Some(out.rows);
    }
    out
}

/// Visibility witnesses indexed once, on the first selected migration chunk.
/// Building visits each verified balance and contributing leaf once; queries
/// perform at most two logarithmic map lookups per leg, regardless of the
/// number of balance claims or chunks in their histories.
#[derive(Default)]
struct MigrationVisibility {
    cells: BTreeMap<(u128, u32), MigrationCoverage>,
}

struct MigrationCoverage {
    /// Greatest cutoff among all balance claims over this cell.
    through: i32,
    /// Greatest cutoff among the claims that actually read each leaf. A
    /// union of leaf IDs alone would incorrectly accept a leaf whose only
    /// witness ends before its day, when a later claim covers but hides it.
    read_through: BTreeMap<u64, i32>,
}

impl MigrationVisibility {
    fn new<'a, I: IntoIterator<Item = &'a u64>>(
        balances: impl IntoIterator<Item = (&'a crate::BalanceClaim, I)>,
    ) -> Self {
        let mut index = Self::default();
        for (claim, contributing) in balances {
            // Civil days are i32, so an unbounded claim covers exactly the
            // same possible days as one ending at i32::MAX.
            let through = claim.effective_through.unwrap_or(i32::MAX);
            let coverage = index
                .cells
                .entry((claim.account, claim.unit))
                .or_insert_with(|| MigrationCoverage {
                    through,
                    read_through: BTreeMap::new(),
                });
            coverage.through = coverage.through.max(through);
            for &leaf in contributing {
                coverage
                    .read_through
                    .entry(leaf)
                    .and_modify(|cutoff| *cutoff = (*cutoff).max(through))
                    .or_insert(through);
            }
        }
        index
    }

    /// Whether the chunk counts (fa-mv0f). A verified balance over one of
    /// its cells, cut off on or after its day, decides that from its run
    /// bodies. `Some(true)` means such a balance read it; `Some(false)`
    /// means covering balances exist but none read it; `None` means its
    /// visibility is unproven. Only migration-aware proofs can verify a
    /// balance over a cell containing a migration chunk.
    fn chunk_visibility<'a>(
        &self,
        leaf: u64,
        day: i32,
        legs: impl IntoIterator<Item = &'a Leg>,
    ) -> Option<bool> {
        let mut covered = false;
        for leg in legs {
            let Some(coverage) = self.cells.get(&(leg.account, leg.unit)) else {
                continue;
            };
            if coverage.through < day {
                continue;
            }
            covered = true;
            if coverage
                .read_through
                .get(&leaf)
                .is_some_and(|through| *through >= day)
            {
                return Some(true);
            }
        }
        covered.then_some(false)
    }
}

/// The registered account type names (`account_types.toml`, tags 1..=8),
/// as the ADS writer prints them; a test cross-checks the registry.
const ACCOUNT_TYPE_NAMES: [&str; 8] = [
    "Asset",
    "Liability",
    "Equity",
    "Revenue",
    "Expense",
    "Memo",
    "Statistical",
    "OffBalance",
];
/// The Chart_of_Accounts header `fa export ads` writes.
pub const CHART_HEADER: &str = "GL_Account_Number|GL_Account_Name|Account_Type|Normal_Balance";

/// The ADS Chart_of_Accounts rows as stated.
fn ads_chart(chart: &str, escaped: bool) -> Result<Vec<StatedAccount>, String> {
    let mut lines = chart.split('\n');
    if lines.next() != Some(CHART_HEADER) {
        return Err("Chart_of_Accounts does not start with the ADS chart header".into());
    }
    lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let decoded = fields(line, escaped, false)?;
            let [code, name, account_type, side] = <[String; 4]>::try_from(decoded)
                .map_err(|_| format!("Chart_of_Accounts row `{line}` has not four fields"))?;
            Ok(StatedAccount {
                line: line.to_string(),
                code,
                name,
                account_type,
                side,
                roles: None,
            })
        })
        .collect()
}

/// ADS's [`chart_matches`] over Chart_of_Accounts text.
#[cfg(test)]
fn chart_rows(
    chart: &str,
    declared: &BTreeMap<u128, crate::report::DeclaredAccount>,
    extract: &[Extracted],
    scope: Option<&str>,
    escaped: bool,
) -> Result<u64, String> {
    chart_matches(
        &ads_chart(chart, escaped)?,
        declared,
        extract,
        scope,
        &ADS_PARTS,
    )
}

/// Check `stated` is exactly the declared chart's rows, in code order: the
/// whole chart, or for one account's extract the accounts its rows and its
/// scope name. Each row states the declared code, name, registered type
/// name and normal balance (D or C). Returns the row count.
pub(crate) fn chart_matches(
    stated: &[StatedAccount],
    declared: &BTreeMap<u128, crate::report::DeclaredAccount>,
    extract: &[Extracted],
    scope: Option<&str>,
    parts: &Parts,
) -> Result<u64, String> {
    let mut expected: Vec<&crate::report::DeclaredAccount> = match scope {
        None => declared.values().collect(),
        Some(code) => {
            let named: std::collections::BTreeSet<&str> = extract
                .iter()
                .flat_map(|entry| entry.rows.iter().map(|row| row.account.as_str()))
                .chain([code])
                .collect();
            declared
                .values()
                .filter(|account| named.contains(account.code.as_str()))
                .collect()
        }
    };
    expected.sort_by(|a, b| a.code.cmp(&b.code));
    if stated.len() != expected.len() {
        return Err(format!(
            "{} has {} rows; the proven chart declares {} for this extract",
            parts.chart,
            stated.len(),
            expected.len()
        ));
    }
    for (row, account) in stated.iter().zip(&expected) {
        let type_name = usize::from(account.account_type)
            .checked_sub(1)
            .and_then(|i| ACCOUNT_TYPE_NAMES.get(i))
            .copied();
        let side = if account.normal_balance == 1 {
            "C"
        } else {
            "D"
        };
        let agrees = row.code == account.code
            && row.name == account.name
            && type_name.is_some_and(|name| row.account_type == name)
            && row.side == side
            && row
                .roles
                .as_ref()
                .is_none_or(|roles| *roles == account.roles);
        if !agrees {
            return Err(format!(
                "{} row `{}` is not the proven declaration of account {} ({}, {}, {side})",
                parts.chart,
                row.line,
                account.code,
                account.name,
                type_name.unwrap_or("an unregistered type")
            ));
        }
    }
    u64::try_from(stated.len()).map_err(|_| format!("{} row count", parts.chart))
}

/// The ADS Trial_Balance rows as stated.
fn ads_balances(trial_balance: &str, escaped: bool) -> Result<Vec<StatedBalance>, String> {
    let mut lines = trial_balance.split('\n');
    if lines.next() != Some(TB_HEADER) {
        return Err("Trial_Balance does not start with the ADS trial balance header".into());
    }
    lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            let decoded = fields(line, escaped, false)?;
            let [account, as_of, side, amount, unit, scale] = <[String; 6]>::try_from(decoded)
                .map_err(|_| format!("Trial_Balance row `{line}` has not six fields"))?;
            Ok(StatedBalance {
                line: line.to_string(),
                account,
                as_of,
                side,
                amount,
                unit,
                scale: Some(
                    scale
                        .parse()
                        .map_err(|_| format!("Trial_Balance row `{line}`: Unit_Scale"))?,
                ),
            })
        })
        .collect()
}

/// ADS's [`balance_rows`] over Trial_Balance text.
#[cfg(test)]
fn trial_balance_rows(
    trial_balance: &str,
    extract: &[Extracted],
    cutoff: &str,
    escaped: bool,
    scope: Option<&str>,
) -> Result<u64, String> {
    balance_rows(
        &ads_balances(trial_balance, escaped)?,
        extract,
        cutoff,
        scope,
        &ADS_PARTS,
    )
}

/// Check `stated` is exactly the refold of the extract's rows: one row per
/// (account, currency) in that order, as of `cutoff`, the signed sum of its
/// legs (debits positive) stated as D (zero or more) or C with its
/// magnitude at the currency's one scale. A scoped extract folds its
/// account's rows only: the other legs of its entries are context. Returns
/// the row count.
pub(crate) fn balance_rows(
    stated: &[StatedBalance],
    extract: &[Extracted],
    cutoff: &str,
    scope: Option<&str>,
    parts: &Parts,
) -> Result<u64, String> {
    let mut folded: BTreeMap<(&str, &str), (i128, u32)> = BTreeMap::new();
    for row in extract
        .iter()
        .flat_map(|entry| &entry.rows)
        .filter(|row| scope.is_none_or(|code| row.account == code))
    {
        let cell = folded
            .entry((row.account.as_str(), row.unit.as_str()))
            .or_insert((0, row.scale));
        if cell.1 != row.scale {
            return Err(format!(
                "{} states two scales for {}",
                parts.entries, row.unit
            ));
        }
        let moved = if row.debit {
            cell.0.checked_add(row.mantissa)
        } else {
            cell.0.checked_sub(row.mantissa)
        };
        cell.0 = moved
            .ok_or_else(|| format!("a {} balance exceeds the exact fold range", parts.entries))?;
    }
    if stated.len() != folded.len() {
        return Err(format!(
            "{} has {} rows; the proven {} folds to {} (account, currency) balances",
            parts.balances,
            stated.len(),
            parts.entries,
            folded.len()
        ));
    }
    for (row, ((account, unit), (balance, scale))) in stated.iter().zip(&folded) {
        let magnitude = balance
            .checked_abs()
            .ok_or_else(|| format!("a {} balance exceeds the exact fold range", parts.entries))?;
        let side = if *balance < 0 { "C" } else { "D" };
        let agrees = row.account == *account
            && row.as_of == cutoff
            && row.side == side
            && row.scale.is_none_or(|stated| stated == *scale)
            && exact(&row.amount, *scale) == Some(magnitude)
            && row.unit == *unit;
        if !agrees {
            return Err(format!(
                "{} row `{}` is not the refold of the proven {} ({account} {unit}: {side} {magnitude} at scale {scale}, as of {cutoff})",
                parts.balances, row.line, parts.entries
            ));
        }
    }
    u64::try_from(stated.len()).map_err(|_| format!("{} row count", parts.balances))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_wire_is_canonical_bounded_and_independent_of_the_exporter() {
        let first = "3:00000000000000000000000000000011";
        let second = "7:00000000000000000000000000000022";
        assert_eq!(dimension_set(""), Ok(vec![]));
        assert_eq!(
            dimension_set(&format!("{first};{second}")),
            Ok(vec![(3, 17), (7, 34)])
        );
        for bad in [
            format!("{first};{first}"),
            format!("{second};{first}"),
            format!("{first};"),
            format!(";{first}"),
            first.replacen("3:", "03:", 1),
            first.replacen("3:", "+3:", 1),
            first.replacen("3:", "4294967296:", 1),
            first.replacen("3:", "-1:", 1),
            first.replace("11", "AA"),
            format!(" {first}"),
            format!("{first} "),
            first[..first.len() - 1].to_string(),
            format!("{first}0"),
        ] {
            assert!(dimension_set(&bad).is_err(), "{bad:?}");
        }
        let full = (0..64)
            .map(|kind| format!("{kind}:{kind:032x}"))
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(dimension_set(&full).unwrap().len(), 64);
        assert!(dimension_set(&format!("{full};64:{:032x}", 64)).is_err());
    }

    #[test]
    fn dimension_extension_requires_its_marker_header_and_every_row() {
        let marker = "dimension_encoding = \"fa-dimension-ids-v1\"\n";
        assert_eq!(dimension_encoding(""), Ok(false));
        assert_eq!(dimension_encoding(marker), Ok(true));
        assert!(dimension_encoding(&format!("{marker}{marker}")).is_err());
        assert!(dimension_encoding(&marker.replace("v1", "v2")).is_err());
        assert!(dimension_encoding(&marker.replace('"', "")).is_err());
        let gl = format!(
            "{GL_HEADER}|{DIMENSION_HEADER}\nentry|1|1970-01-01|7|1|1000|D|12.34|USD|2|tagged|||3:00000000000000000000000000000011\nentry|2|1970-01-01|7|1|3000|C|12.34|USD|2|tagged|||\n"
        );
        let rows = &extracted(&gl, false, true).unwrap()[0].rows;
        assert_eq!(rows[0].dimensions, Some(vec![(3, 17)]));
        assert_eq!(rows[1].dimensions, Some(vec![]));
        assert!(extracted(&gl, false, false).is_err());
        assert!(
            extracted(
                &gl.replace(&format!("|{DIMENSION_HEADER}"), ""),
                false,
                true
            )
            .is_err()
        );
        assert!(extracted(&gl.replace("|tagged|||\n", "|tagged||\n"), false, true).is_err());
    }

    #[test]
    fn dimension_only_changes_refuse_against_native_proposal_leg_details() {
        use crate::codec::Writer;
        use crate::envelope::{
            ENTRY_DIGEST_DOMAIN, PROPOSAL_DIGEST_DOMAIN, check_record, envelope_of_entry,
        };

        // Independent native bytes, not a fa-formats export. The entry's
        // authenticated digest binds both tagged and untagged legs.
        let book = [0x51; 16];
        let mut wire = Writer::default();
        wire.u16(1)
            .u16(1)
            .fixed(&book)
            .fixed(&[0; 16])
            .u16(1)
            .i32(0)
            .u8(0)
            .fixed(&[0; 32])
            .u8(0)
            .fixed(&[0; 24])
            .bytes(b"tagged")
            .u8(0)
            .count(2);
        let mut first_value_offset = 0;
        for (code, side, tags) in [
            ("1000", 0, vec![(3u32, 17u128), (7, 34)]),
            ("3000", 1, vec![]),
        ] {
            wire.u8(side)
                .u128(account_vid(&book, code))
                .u32(1)
                .i128(1234)
                .u8(0)
                .count(tags.len());
            for (kind, value) in tags {
                wire.u32(kind);
                if first_value_offset == 0 {
                    first_value_offset = wire.buf.len();
                }
                wire.u128(value);
            }
            wire.u8(0).count(0);
        }
        wire.u8(0)
            .count(1)
            .u32(1)
            .i128(1234)
            .i128(1234)
            .u8(0)
            .bytes(b"dim-export")
            .u8(0)
            .fixed(&[9; 32])
            .u16(1)
            .u128(7)
            .u8(0)
            .count(0)
            .count(0)
            .u8(0)
            .count(0)
            .count(0)
            .count(0);
        let split = wire.buf.len();
        let proposal_digest = hash_parts(PROPOSAL_DIGEST_DOMAIN, &[&wire.buf]);
        let entry_digest = hash_parts(ENTRY_DIGEST_DOMAIN, &[&proposal_digest, &[0; 5]]);
        wire.fixed(&[0; 5])
            .fixed(&proposal_digest)
            .fixed(&entry_digest);
        let envelope = envelope_of_entry(&wire.buf, split, 7, 0).unwrap();
        let legs = check_record(&envelope, &wire.buf, split).unwrap();
        let dimensions = proposal_leg_details(&wire.buf[..split])
            .unwrap()
            .into_iter()
            .map(|detail| detail.dimensions)
            .collect();
        let proven = Proven {
            class: 1,
            date: "1970-01-01".into(),
            legs,
            dimensions,
        };
        let gl = format!(
            "{GL_HEADER}|{DIMENSION_HEADER}\nentry|1|1970-01-01|7|1|1000|D|12.34|USD|2|tagged|||3:00000000000000000000000000000011;7:00000000000000000000000000000022\nentry|2|1970-01-01|7|1|3000|C|12.34|USD|2|tagged|||\n"
        );
        let extract = extracted(&gl, false, true).unwrap();
        assert!(same(&extract[0], &proven, &book, &Units::default()));
        for changed in [
            gl.replace(
                "00000000000000000000000000000011",
                "00000000000000000000000000000012",
            ),
            gl.replace("3:00000000000000000000000000000011;", ""),
            gl.replace(
                "|tagged|||\n",
                "|tagged|||3:00000000000000000000000000000011\n",
            ),
        ] {
            let changed = extracted(&changed, false, true).unwrap();
            assert!(!same(&changed[0], &proven, &book, &Units::default()));
        }
        let mut altered_payload = wire.buf.clone();
        altered_payload[first_value_offset] ^= 1;
        assert!(check_record(&envelope, &altered_payload, split).is_err());
        let legacy = format!(
            "{GL_HEADER}\nentry|1|1970-01-01|7|1|1000|D|12.34|USD|2|tagged||\nentry|2|1970-01-01|7|1|3000|C|12.34|USD|2|tagged||\n"
        );
        let legacy = extracted(&legacy, false, false).unwrap();
        assert!(legacy[0].rows.iter().all(|row| row.dimensions.is_none()));
        assert!(same(&legacy[0], &proven, &book, &Units::default()));
    }

    fn count_match_visit(work: &mut [u64; 5], visit: MatchVisit) {
        let index = match visit {
            MatchVisit::AccountHash => 0,
            MatchVisit::UnitGroup => 1,
            MatchVisit::Candidate => 2,
            MatchVisit::DimensionIndexRow => 3,
            MatchVisit::UnitIndexLeg => 4,
        };
        work[index] += 1;
    }

    fn matching_record(book: &[u8; 16], amount: i128, units: [u32; 2], tag: u128) -> Proven {
        Proven {
            class: 1,
            date: "1970-01-01".into(),
            legs: ["1000", "4000"]
                .into_iter()
                .enumerate()
                .map(|(i, code)| Leg {
                    debit: i == 0,
                    account: account_vid(book, code),
                    unit: units[i],
                    mantissa: amount,
                })
                .collect(),
            dimensions: vec![vec![(3, tag)], vec![]],
        }
    }

    fn matching_extract(
        record: &Proven,
        seq: u64,
        units: [&str; 2],
        dimension_mask: u8,
    ) -> Extracted {
        Extracted {
            journal_id: "batch-entry".into(),
            seq,
            date: record.date.clone(),
            class: record.class,
            rows: record
                .legs
                .iter()
                .enumerate()
                .map(|(i, leg)| Row {
                    journal_id: "batch-entry".into(),
                    line: u32::try_from(i + 1).unwrap(),
                    date: record.date.clone(),
                    seq,
                    class: record.class,
                    account: ["1000", "4000"][i].into(),
                    debit: leg.debit,
                    mantissa: leg.mantissa,
                    unit: units[i].into(),
                    scale: 2,
                    dimensions: (dimension_mask & (1 << i) != 0)
                        .then(|| record.dimensions[i].clone()),
                })
                .collect(),
        }
    }

    fn pair_account(pair: usize, debit: bool) -> String {
        format!("{}000", pair + if debit { 1 } else { 4 })
    }

    fn balanced_matching_record(book: &[u8; 16], units: &[u32]) -> Proven {
        let legs: Vec<_> = units
            .iter()
            .enumerate()
            .flat_map(|(pair, &unit)| {
                [true, false].map(|debit| Leg {
                    debit,
                    account: account_vid(book, &pair_account(pair, debit)),
                    unit,
                    mantissa: 5,
                })
            })
            .collect();
        Proven {
            class: 1,
            date: "1970-01-01".into(),
            dimensions: vec![vec![(3, 11)]; legs.len()],
            legs,
        }
    }

    fn balanced_matching_extract(
        record: &Proven,
        units: &[&str],
        full_dimensions: bool,
    ) -> Extracted {
        Extracted {
            journal_id: "currency-pairs".into(),
            seq: 7,
            date: record.date.clone(),
            class: record.class,
            rows: record
                .legs
                .iter()
                .enumerate()
                .map(|(i, leg)| Row {
                    journal_id: "currency-pairs".into(),
                    line: u32::try_from(i + 1).unwrap(),
                    date: record.date.clone(),
                    seq: 7,
                    class: record.class,
                    account: pair_account(i / 2, leg.debit),
                    debit: leg.debit,
                    mantissa: leg.mantissa,
                    unit: units[i / 2].into(),
                    scale: 2,
                    dimensions: full_dimensions.then(|| record.dimensions[i].clone()),
                })
                .collect(),
        }
    }

    fn assert_matching_agrees_with_literal_scan(
        book: [u8; 16],
        mut literal: BTreeMap<u64, Vec<Proven>>,
        entries: &[Extracted],
        initial: &Units,
    ) {
        let mut indexed = ProvenMatcher::new(
            literal
                .clone()
                .into_iter()
                .flat_map(|(seq, records)| records.into_iter().map(move |record| (seq, record))),
            book,
        );
        let mut expected_units = Units {
            by_code: initial.by_code.clone(),
            by_id: initial.by_id.clone(),
        };
        let mut actual_units = Units {
            by_code: initial.by_code.clone(),
            by_id: initial.by_id.clone(),
        };
        for (query, entry) in entries.iter().enumerate() {
            // Keep the original search and removal here: this oracle must
            // not depend on the indexed key, unit grouping or queue logic.
            let expected = literal.get_mut(&entry.seq).and_then(|list| {
                list.iter()
                    .position(|record| same(entry, record, &book, &expected_units))
                    .map(|i| list.remove(i))
            });
            let actual = indexed.take(entry, &actual_units, |_| {});
            assert_eq!(actual, expected, "query {query}: {entry:?}");
            for (matched, units) in [
                (expected.as_ref(), &mut expected_units),
                (actual.as_ref(), &mut actual_units),
            ] {
                if let Some(matched) = matched {
                    for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                        units.by_code.insert(row.unit.clone(), leg.unit);
                        units.by_id.insert(leg.unit, row.unit.clone());
                    }
                }
            }
            assert_eq!(actual_units.by_code, expected_units.by_code);
            assert_eq!(actual_units.by_id, expected_units.by_id);
        }
        let expected: Vec<_> = literal
            .iter()
            .flat_map(|(seq, records)| records.iter().map(move |record| (*seq, record)))
            .collect();
        assert_eq!(indexed.remaining().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn indexed_batch_matching_preserves_order_units_wildcards_and_missing_records() {
        let book = [0x72; 16];
        let originals = vec![
            matching_record(&book, 5, [9, 9], 11),
            matching_record(&book, 5, [2, 2], 22),
            matching_record(&book, 5, [9, 9], 22),
            matching_record(&book, 5, [4, 5], 33),
            matching_record(&book, 8, [2, 2], 11),
            matching_record(&book, 5, [5, 4], 33),
        ];
        let initial = [
            Units::default(),
            Units {
                by_code: [("USD".into(), 9)].into(),
                by_id: [(9, "USD".into())].into(),
            },
            // A previously inferred contradictory code pair remains a
            // refusal, even on the direct known-unit lookup path.
            Units {
                by_code: [("USD".into(), 9), ("EUR".into(), 9)].into(),
                by_id: [(9, "EUR".into())].into(),
            },
        ];
        for rotation in 0..originals.len() {
            let mut batch = originals.clone();
            batch.rotate_left(rotation);
            for reversed in [false, true] {
                if reversed {
                    batch.reverse();
                }
                for dimension_mask in [0, 1, 2, 3] {
                    let mut later = originals[0].clone();
                    later.date = "1970-01-02".into();
                    later.class = 3;
                    let records: BTreeMap<_, _> =
                        [(7, batch.clone()), (9, vec![later.clone()])].into();
                    let mut entries: Vec<_> = originals
                        .iter()
                        .enumerate()
                        .map(|(i, record)| {
                            let units = match i % 4 {
                                0 => ["USD", "USD"],
                                1 => ["EUR", "EUR"],
                                2 => ["USD", "EUR"],
                                _ => ["X", "Y"],
                            };
                            matching_extract(record, 7, units, dimension_mask)
                        })
                        .collect();
                    entries.rotate_left(rotation);
                    if reversed {
                        entries.reverse();
                    }
                    entries.push(matching_extract(&later, 9, ["X", "X"], dimension_mask));
                    // Vary every matching field. When dimensions are
                    // omitted, the last variant deliberately stays a
                    // wildcard and can consume another duplicate.
                    for field in 0..8 {
                        let mut changed = entries[0].clone();
                        match field {
                            0 => changed.seq = 8,
                            1 => changed.rows[0].account = "9999".into(),
                            2 => changed.rows[0].debit = !changed.rows[0].debit,
                            3 => changed.rows[0].mantissa += 1,
                            4 => changed.class = 99,
                            5 => changed.date = "1970-01-03".into(),
                            6 => {
                                changed.rows.pop();
                            }
                            _ => {
                                if let Some(dimensions) = &mut changed.rows[0].dimensions {
                                    dimensions.push((7, 99));
                                }
                            }
                        }
                        entries.push(changed);
                    }
                    entries.push(entries[0].clone()); // duplicate consumption
                    for initial in &initial {
                        assert_matching_agrees_with_literal_scan(
                            book,
                            records.clone(),
                            &entries,
                            initial,
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn mixed_dimension_matching_skips_interior_records_without_changing_the_first_match() {
        let book = [0x43; 16];
        let first = matching_record(&book, 5, [9, 9], 11);
        let second = matching_record(&book, 5, [2, 2], 22);
        let third = matching_record(&book, 5, [9, 9], 22);
        // The first unit group can match the third record, but the second
        // group has an earlier match. Its unit ID must win the inference.
        let entries = [
            matching_extract(&second, 7, ["USD", "USD"], 3),
            matching_extract(&third, 7, ["EUR", "EUR"], 1),
            matching_extract(&first, 7, ["EUR", "EUR"], 0),
            matching_extract(&third, 7, ["EUR", "EUR"], 0),
        ];
        assert_matching_agrees_with_literal_scan(
            book,
            [(7, vec![first, second, third])].into(),
            &entries,
            &Units::default(),
        );
    }

    #[test]
    fn full_partial_and_wildcard_queries_retire_both_dimension_indexes() {
        let book = [0x44; 16];
        let records: Vec<_> = (0..8)
            .map(|tag| matching_record(&book, 5, [9, 9], tag))
            .collect();
        // The dimensional index is first built after an interior record
        // and the original head were consumed through the other index.
        // Later full/partial/wildcard queries must not resurrect either
        // record, and advancing a head must skip all old tombstones.
        let entries: Vec<_> = [
            (5, 1),
            (0, 0),
            (7, 3),
            (5, 3),
            (7, 1),
            (1, 0),
            (0, 3),
            (2, 3),
            (3, 0),
            (3, 3),
            (4, 3),
            (6, 0),
            (6, 3),
        ]
        .into_iter()
        .map(|(record, mask)| matching_extract(&records[record], 7, ["USD", "USD"], mask))
        .collect();
        assert_matching_agrees_with_literal_scan(
            book,
            [(7, records)].into(),
            &entries,
            &Units::default(),
        );
    }

    #[test]
    fn partially_known_unit_index_preserves_earliest_group_and_removes_empty_groups() {
        let book = [0x45; 16];
        let earlier = matching_record(&book, 5, [9, 7], 11);
        let later = matching_record(&book, 5, [9, 2], 11);
        let entries = [
            matching_extract(&earlier, 7, ["USD", "NEW"], 0),
            matching_extract(&later, 7, ["USD", "OTHER"], 0),
            matching_extract(&earlier, 7, ["USD", "NEW"], 0),
            matching_extract(&later, 7, ["USD", "FRESH"], 0),
        ];
        assert_matching_agrees_with_literal_scan(
            book,
            [(7, vec![earlier.clone(), later, earlier])].into(),
            &entries,
            &Units {
                by_code: [("USD".into(), 9)].into(),
                by_id: [(9, "USD".into())].into(),
            },
        );
    }

    #[test]
    fn smallest_unit_posting_list_still_checks_other_known_units_in_both_indexes() {
        let book = [0x48; 16];
        // Each currency has a balanced debit/credit pair. The EUR=2 list
        // is narrower than USD=9, but its earliest member has USD=8 and
        // must be skipped. Both dimensional and wildcard indexes are used.
        let records: Vec<_> = [
            [8, 2, 7],
            [9, 2, 7],
            [9, 2, 6],
            [9, 3, 7],
            [9, 4, 7],
            [9, 2, 6],
        ]
        .iter()
        .map(|units| balanced_matching_record(&book, units))
        .collect();
        let entries = [
            balanced_matching_extract(&records[1], &["USD", "EUR", "NEW"], false),
            balanced_matching_extract(&records[2], &["USD", "EUR", "ALT"], true),
            balanced_matching_extract(&records[1], &["USD", "EUR", "NEW"], true),
            balanced_matching_extract(&records[2], &["USD", "EUR", "ALT"], false),
            balanced_matching_extract(&records[2], &["USD", "EUR", "ALT"], true),
        ];
        assert_matching_agrees_with_literal_scan(
            book,
            [(7, records)].into(),
            &entries,
            &Units {
                by_code: [("USD".into(), 9), ("EUR".into(), 2)].into(),
                by_id: [(9, "USD".into()), (2, "EUR".into())].into(),
            },
        );
    }

    #[test]
    fn identical_and_reversed_hundred_thousand_entry_batches_match_once_per_entry() {
        let book = [0x28; 16];
        let template = matching_record(&book, 5, [9, 9], 11);
        for count in [1_000u64, 10_000, 100_000] {
            for shape in 0..3 {
                for full_dimensions in [false, true] {
                    let record = |index: u64| {
                        let mut native = template.clone();
                        if shape == 1 {
                            for leg in &mut native.legs {
                                leg.mantissa += i128::from(index);
                            }
                        } else if shape == 2 {
                            native.dimensions[0] = vec![(3, u128::from(index))];
                        }
                        native
                    };
                    let mut loaded = 0u64;
                    let mut indexed = ProvenMatcher::new(
                        (0..count).map(|i| (7, record(i))).inspect(|_| loaded += 1),
                        book,
                    );
                    let mut units = Units::default();
                    let mut work = [0u64; 5];
                    for step in 0..count {
                        let source = count - step - 1;
                        let entry = matching_extract(
                            &record(source),
                            7,
                            ["USD", "USD"],
                            if full_dimensions { 3 } else { 0 },
                        );
                        let matched = indexed
                            .take(&entry, &units, |visit| {
                                count_match_visit(&mut work, visit);
                            })
                            .expect("a matching batch entry remains");
                        // Legacy extracts cannot distinguish dimensions:
                        // the original FIFO order wins even when the
                        // originating rows were emitted in reverse order.
                        let expected = if shape == 2 && !full_dimensions {
                            step
                        } else {
                            source
                        };
                        assert_eq!(matched, record(expected));
                        for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                            units.by_code.insert(row.unit.clone(), leg.unit);
                            units.by_id.insert(leg.unit, row.unit.clone());
                        }
                    }
                    assert_eq!(loaded, count);
                    assert_eq!(
                        work,
                        [2, count, count, if full_dimensions { count } else { 0 }, 0],
                        "size {count}, shape {shape}"
                    );
                    assert_eq!(indexed.remaining().count(), 0);
                    let duplicate = matching_extract(
                        &template,
                        7,
                        ["USD", "USD"],
                        if full_dimensions { 3 } else { 0 },
                    );
                    assert!(indexed.take(&duplicate, &units, |_| {}).is_none());
                }
            }
        }
    }

    #[test]
    fn one_wildcard_does_not_rescan_a_hundred_thousand_dimensioned_candidates() {
        let book = [0x46; 16];
        let template = matching_record(&book, 5, [9, 9], 11);
        for count in [1_000u64, 10_000, 100_000] {
            for wildcard_first in [false, true] {
                let record = |tag: u64| {
                    let mut native = template.clone();
                    native.dimensions[0] = vec![(3, u128::from(tag))];
                    native
                };
                let mut indexed = ProvenMatcher::new((0..count).map(|i| (7, record(i))), book);
                let mut units = Units::default();
                let mut work = [0; 5];
                let mut take = |source: u64, mask: u8| {
                    let expected = record(source);
                    let entry = matching_extract(&expected, 7, ["USD", "USD"], mask);
                    let matched = indexed
                        .take(&entry, &units, |visit| count_match_visit(&mut work, visit))
                        .unwrap();
                    assert_eq!(matched, expected);
                    for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                        units.by_code.insert(row.unit.clone(), leg.unit);
                        units.by_id.insert(leg.unit, row.unit.clone());
                    }
                };
                if wildcard_first {
                    take(0, 0);
                    for tag in (1..count).rev() {
                        take(tag, 3);
                    }
                } else {
                    take(count - 1, 3);
                    take(0, 0);
                    for tag in (1..count - 1).rev() {
                        take(tag, 3);
                    }
                }
                assert_eq!(
                    work,
                    [2, count, count, count - u64::from(wildcard_first), 0]
                );
                assert_eq!(indexed.remaining().count(), 0);
            }
        }
    }

    #[test]
    fn partially_known_units_probe_one_group_in_a_hundred_thousand_entry_batch() {
        let book = [0x47; 16];
        let template = matching_record(&book, 5, [1, 2], 11);
        for count in [1_000u32, 10_000, 100_000] {
            let record = |index: u32| {
                let mut native = template.clone();
                native.legs[0].unit = index + 1;
                native.legs[1].unit = count + index + 1;
                native
            };
            let mut indexed = ProvenMatcher::new((0..count).map(|i| (7, record(i))), book);
            let mut units = Units::default();
            for i in 0..count {
                let code = format!("known-{i}");
                units.by_code.insert(code.clone(), i + 1);
                units.by_id.insert(i + 1, code);
            }
            let mut work = [0; 5];
            for i in (0..count).rev() {
                let expected = record(i);
                let known = format!("known-{i}");
                let fresh = format!("new-{i}");
                let entry = matching_extract(&expected, 7, [&known, &fresh], 0);
                let matched = indexed
                    .take(&entry, &units, |visit| count_match_visit(&mut work, visit))
                    .unwrap();
                assert_eq!(matched, expected);
                for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                    units.by_code.insert(row.unit.clone(), leg.unit);
                    units.by_id.insert(leg.unit, row.unit.clone());
                }
            }
            let count = u64::from(count);
            assert_eq!(work, [2, count, count, 0, 2 * count]);
            assert_eq!(indexed.remaining().count(), 0);
        }
    }

    #[test]
    fn shared_known_unit_stops_at_the_first_of_a_hundred_thousand_partial_groups() {
        let book = [0x49; 16];
        let template = balanced_matching_record(&book, &[1, 2]);
        for count in [1_000u32, 10_000, 100_000] {
            for full_dimensions in [false, true] {
                let record = |group: u32| {
                    let mut native = template.clone();
                    for leg in &mut native.legs[2..] {
                        leg.unit = group + 2;
                    }
                    native
                };
                // Every group shares the known USD debit/credit pair;
                // its second balanced currency pair starts with an
                // unknown display code. Duplicates appended at the end
                // keep every tenth group live after its first match, so
                // inverted memberships must MOVE when heads advance.
                let mut indexed = ProvenMatcher::new(
                    (0..count)
                        .chain((0..count).step_by(10))
                        .map(|group| (7, record(group))),
                    book,
                );
                let mut units = Units {
                    by_code: [("USD".into(), 1)].into(),
                    by_id: [(1, "USD".into())].into(),
                };
                let mut work = [0; 5];
                let mut take = |group: u32, dimensions: bool| {
                    let expected = record(group);
                    let fresh = format!("currency-{group}");
                    let entry = balanced_matching_extract(&expected, &["USD", &fresh], dimensions);
                    let matched = indexed
                        .take(&entry, &units, |visit| count_match_visit(&mut work, visit))
                        .unwrap();
                    assert_eq!(matched, expected);
                    for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                        units.by_code.insert(row.unit.clone(), leg.unit);
                        units.by_id.insert(leg.unit, row.unit.clone());
                    }
                };
                for group in 0..count {
                    // Start with a wildcard so the dimensional case
                    // exercises both sets of inverted memberships.
                    take(group, full_dimensions && group != 0);
                }
                for group in (0..count).rev().filter(|group| group.is_multiple_of(10)) {
                    take(group, full_dimensions);
                }
                let entries = u64::from(count + count.div_ceil(10));
                let indexed_legs = u64::from(count) * if full_dimensions { 8 } else { 4 };
                assert_eq!(
                    work,
                    [
                        4,
                        entries,
                        entries,
                        if full_dimensions { entries - 1 } else { 0 },
                        indexed_legs,
                    ]
                );
                assert_eq!(indexed.remaining().count(), 0);
            }
        }
    }

    #[test]
    fn v3_text_decodes_without_the_writer_and_rejects_noncanonical_escapes() {
        assert_eq!(
            decode_field(r"one\nline\rreturn\ppipe\\literal\u0009\u0000\u0085 café").unwrap(),
            "one\nline\rreturn|pipe\\literal\t\0\u{85} café"
        );
        for bad in ["\\q", "\\", "\\uD800", "\\u000a", "\\u001F", "\t", "\\N"] {
            assert!(decode_field(bad).is_err(), "bad text {bad:?}");
        }
        let gl = format!(
            "{GL_HEADER}\nentry\\pid|1|2026-03-10|7|1|60\\p00|D|15.00|USD|2|one\\nline|\\N|\n"
        );
        let entries = extracted(&gl, true, false).unwrap();
        assert_eq!(entries[0].journal_id, "entry|id");
        assert_eq!(entries[0].rows[0].account, "60|00");
        let tb = format!("{TB_HEADER}\n60\\p00|2026-03-31|D|15.00|USD|2\n");
        assert_eq!(
            trial_balance_rows(&tb, &entries, "2026-03-31", true, None),
            Ok(1)
        );
        assert!(
            trial_balance_rows(
                &tb.replace("15.00", "15.01"),
                &entries,
                "2026-03-31",
                true,
                None
            )
            .is_err()
        );
        // A literal backslash in the existing v2 profile keeps its meaning.
        let legacy = extracted(&gl, false, false).unwrap();
        assert_eq!(legacy[0].journal_id, r"entry\pid");
    }

    #[test]
    fn v4_derived_balances_use_escaped_text_and_require_the_exact_gl_fold() {
        let certificate = "format = \"aicpa_ads_gl_v4\"\naccount_scope_utf8_hex = \"36307c3030\"\n";
        let escaped = escaped_format(certificate).unwrap();
        assert!(escaped);
        let account = utf8_hex(field(certificate, "account_scope_utf8_hex").unwrap()).unwrap();
        assert_eq!(account, "60|00");
        let gl = format!(
            "{GL_HEADER}\nentry\\pid|1|2026-03-10|7|1|60\\p00|D|15.00|USD|2|one\\nline|\\N|\nentry\\pid|2|2026-03-10|7|1|1000|C|15.00|USD|2|one\\nline|\\N|\n"
        );
        let entries = extracted(&gl, escaped, false).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].rows[0].account, account);
        let tb = format!("{TB_HEADER}\n60\\p00|2026-03-31|D|15.00|USD|2\n");
        assert_eq!(
            trial_balance_rows(&tb, &entries, "2026-03-31", escaped, Some(&account)),
            Ok(1)
        );
        for bad in [
            tb.replace("15.00", "15.01"),
            tb.replace("15.00|USD|2", "15.000|USD|3"),
            tb.replace("|D|", "|C|"),
            format!("{TB_HEADER}\n"),
            format!("{tb}1000|2026-03-31|C|15.00|USD|2\n"),
        ] {
            assert!(
                trial_balance_rows(&bad, &entries, "2026-03-31", escaped, Some(&account)).is_err(),
                "{bad}"
            );
        }
        assert!(escaped_format(&certificate.replace("v4", "v5")).is_err());
    }

    #[test]
    fn amounts_are_exact_at_their_scale_and_nothing_else_parses() {
        assert_eq!(exact("1500.00", 2), Some(150_000));
        assert_eq!(exact("0.07", 2), Some(7));
        assert_eq!(exact("12", 0), Some(12));
        for bad in ["1500.0", "1500", ".50", "1,500.00", "-1.00", "1.000", "1e3"] {
            assert_eq!(exact(bad, 2), None, "{bad}");
        }
        assert_eq!(exact("12.0", 0), None);
        assert_eq!(
            exact("99999999999999999999999999999999999999999", 0),
            None,
            "beyond i128 is refused, never wrapped"
        );
    }

    #[test]
    fn rows_group_by_journal_id_numbered_in_order() {
        let gl = format!(
            "{GL_HEADER}\n\
             aa|1|2026-03-10|7|1|6000|D|15.00|USD|2|Rent||\n\
             aa|2|2026-03-10|7|1|1000|C|15.00|USD|2|Rent||\n\
             bb|1|2026-03-11|8|1|1000|D|1.00|USD|2|x||\n"
        );
        let entries = extracted(&gl, false, false).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rows.len(), 2);
        assert!(!entries[0].rows[1].debit);
        assert_eq!(entries[1].rows[0].mantissa, 100);

        let skipped = gl.replace("aa|2|", "aa|3|");
        assert!(
            extracted(&skipped, false, false).is_err(),
            "line 2 is missing"
        );
        let torn = gl.replace("|Rent||\n", "|Ren\nt||\n");
        assert!(
            extracted(&torn, false, false).is_err(),
            "a broken row is refused"
        );
        assert!(
            extracted("Journal_ID|x\n", false, false).is_err(),
            "not the ADS header"
        );
    }

    #[test]
    fn the_trial_balance_is_exactly_the_refold_of_the_rows() {
        let gl = format!(
            "{GL_HEADER}\n\
             aa|1|2026-03-10|7|1|6000|D|15.00|USD|2|Rent||\n\
             aa|2|2026-03-10|7|1|1000|C|15.00|USD|2|Rent||\n\
             bb|1|2026-03-11|8|1|1000|D|1.00|USD|2|x||\n\
             bb|2|2026-03-11|8|1|4000|C|1.00|USD|2|x||\n"
        );
        let extract = extracted(&gl, false, false).unwrap();
        let tb = format!(
            "{TB_HEADER}\n\
             1000|2026-03-31|C|14.00|USD|2\n\
             4000|2026-03-31|C|1.00|USD|2\n\
             6000|2026-03-31|D|15.00|USD|2\n"
        );
        assert_eq!(
            trial_balance_rows(&tb, &extract, "2026-03-31", false, None),
            Ok(3)
        );
        // One account's extract folds that account's rows only: the other
        // legs of its entries are context, and no balance of theirs belongs.
        let cash = format!("{TB_HEADER}\n1000|2026-03-31|C|14.00|USD|2\n");
        assert_eq!(
            trial_balance_rows(&cash, &extract, "2026-03-31", false, Some("1000")),
            Ok(1)
        );
        assert!(
            trial_balance_rows(&tb, &extract, "2026-03-31", false, Some("1000")).is_err(),
            "a contra account's balance is not the scoped account's"
        );
        for bad in [
            tb.replace("C|14.00", "C|14.01"),
            tb.replace("C|14.00", "D|14.00"),
            tb.replace("6000|2026-03-31|D|15.00|USD|2\n", ""),
            format!("{tb}9999|2026-03-31|D|0.00|USD|2\n"),
            tb.replace("2026-03-31|C|1.00", "2026-03-30|C|1.00"),
            tb.replace("14.00|USD|2", "14.000|USD|3"),
            tb.replace("4000|2026-03-31|C|1.00|USD|2\n6000", "6000"),
            tb.replace(TB_HEADER, "GL_Account_Number|As_Of_Date"),
        ] {
            assert!(
                trial_balance_rows(&bad, &extract, "2026-03-31", false, None).is_err(),
                "{bad}"
            );
        }
    }

    fn chunk_visibility<'a>(
        leaf: u64,
        day: i32,
        legs: &[Leg],
        balances: impl IntoIterator<Item = (&'a crate::BalanceClaim, &'a [u64])>,
    ) -> Option<bool> {
        MigrationVisibility::new(balances).chunk_visibility(leaf, day, legs)
    }

    // The original scan is deliberately retained as an independent oracle.
    fn literal_chunk_visibility<'a>(
        leaf: u64,
        day: i32,
        legs: &[Leg],
        balances: impl IntoIterator<Item = (&'a crate::BalanceClaim, &'a [u64])>,
    ) -> Option<bool> {
        let mut covered = false;
        for (claim, contributing) in balances {
            let covers = legs
                .iter()
                .any(|leg| (leg.account, leg.unit) == (claim.account, claim.unit))
                && claim.effective_through.is_none_or(|through| through >= day);
            if covers {
                if contributing.contains(&leaf) {
                    return Some(true);
                }
                covered = true;
            }
        }
        covered.then_some(false)
    }

    #[test]
    fn migration_chunks_follow_their_runs_visibility() {
        let (cash, revenue, usd, day) = (7u128, 9u128, 1u32, 100);
        let legs = [
            Leg {
                debit: true,
                account: cash,
                unit: usd,
                mantissa: 5,
            },
            Leg {
                debit: false,
                account: revenue,
                unit: usd,
                mantissa: 5,
            },
        ];
        let claim = |account, effective_through| crate::BalanceClaim {
            account,
            unit: usd,
            effective_through,
            debits: 0,
            credits: 0,
        };
        let cash_after = claim(cash, Some(120));
        // A covering balance read the chunk: its run makes it visible.
        assert_eq!(
            chunk_visibility(3, day, &legs, [(&cash_after, &[1u64, 3][..])]),
            Some(true)
        );
        // Covering, but not read: its run hides it.
        assert_eq!(
            chunk_visibility(3, day, &legs, [(&cash_after, &[1u64][..])]),
            Some(false)
        );
        // A balance over its other cell decides it as well.
        let revenue_all = claim(revenue, None);
        assert_eq!(
            chunk_visibility(
                3,
                day,
                &legs,
                [(&cash_after, &[][..]), (&revenue_all, &[3u64][..])]
            ),
            Some(true)
        );
        // Planted: a balance over another account, another unit, or cut off
        // before the chunk's day proves nothing about it.
        let other = claim(11, None);
        let euro = crate::BalanceClaim {
            unit: 2,
            ..claim(cash, None)
        };
        let early = claim(cash, Some(day - 1));
        for (balance, why) in [
            (&other, "another account"),
            (&euro, "another unit"),
            (&early, "cut off before its day"),
        ] {
            assert_eq!(
                chunk_visibility(3, day, &legs, [(balance, &[3u64][..])]),
                None,
                "{why}"
            );
        }
        assert_eq!(chunk_visibility(3, day, &legs, std::iter::empty()), None);
    }

    #[test]
    fn migration_visibility_index_matches_scan_for_overlapping_cutoffs() {
        let claim = |account, unit, effective_through| crate::BalanceClaim {
            account,
            unit,
            effective_through,
            debits: 0,
            credits: 0,
        };
        let leg = |account, unit| Leg {
            debit: true,
            account,
            unit,
            mantissa: 5,
        };
        // In particular, the early cash witness reads leaf 0, but the
        // later cash witnesses do not: coverage and membership cutoffs
        // must remain separate. Repeated and unordered leaves must not
        // change this existential decision either.
        let histories = [
            (claim(7, 1, Some(99)), vec![2, 0, 2]),
            (claim(7, 1, Some(100)), vec![1]),
            (claim(7, 1, None), vec![3]),
            (claim(9, 1, Some(101)), vec![0, 4]),
            (claim(7, 2, Some(100)), vec![5]),
            (claim(11, 1, Some(i32::MIN)), vec![6]),
            (claim(11, 1, Some(i32::MAX)), vec![7]),
        ];
        let leg_sets = [
            vec![],
            vec![leg(7, 1)],
            vec![leg(9, 1)],
            vec![leg(7, 2)],
            vec![leg(7, 3)],
            vec![leg(11, 1)],
            vec![leg(7, 1), leg(9, 1)],
            vec![leg(9, 1), leg(7, 1)],
            vec![leg(7, 1), leg(7, 1), leg(7, 2)],
            vec![leg(99, 99)],
        ];
        for mask in 0..(1usize << histories.len()) {
            let mut balances: Vec<_> = histories
                .iter()
                .enumerate()
                .filter(|(i, _)| mask & (1 << i) != 0)
                .map(|(_, (claim, contributing))| (claim, contributing.as_slice()))
                .collect();
            for reverse in [false, true] {
                if reverse {
                    balances.reverse();
                }
                let index = MigrationVisibility::new(balances.iter().copied());
                for day in [i32::MIN, i32::MIN + 1, 98, 99, 100, 101, 102, i32::MAX] {
                    for leaf in 0..9 {
                        for legs in &leg_sets {
                            assert_eq!(
                                index.chunk_visibility(leaf, day, legs),
                                literal_chunk_visibility(leaf, day, legs, balances.iter().copied(),),
                                "claims {mask}, reversed {reverse}, leaf {leaf}, day {day}, legs {legs:?}"
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn migration_visibility_reads_witnesses_once_for_a_hundred_thousand_chunks_and_cells() {
        use std::cell::Cell;

        let claim = |account| crate::BalanceClaim {
            account,
            unit: 1,
            effective_through: Some(100),
            debits: 0,
            credits: 0,
        };
        for count in [1_000u64, 10_000, 100_000] {
            for many_cells in [false, true] {
                // Exercise both original quadratic cases: one cell with
                // a long contributing history, and many balance claims
                // whose chunks would each rescan that claim list.
                let histories: Vec<_> = if many_cells {
                    (0..count)
                        .map(|leaf| (claim(u128::from(leaf)), vec![leaf]))
                        .collect()
                } else {
                    vec![(claim(0), (0..count).collect())]
                };
                let balance_visits = Cell::new(0u64);
                let leaf_visits = Cell::new(0u64);
                let balances = histories.iter().map(|(claim, contributing)| {
                    balance_visits.set(balance_visits.get() + 1);
                    (
                        claim,
                        contributing.iter().inspect(|_| {
                            leaf_visits.set(leaf_visits.get() + 1);
                        }),
                    )
                });
                let index = MigrationVisibility::new(balances);
                let probes = Cell::new(0u64);
                let visibility = |leaf, day, leg: &Leg| {
                    index.chunk_visibility(
                        leaf,
                        day,
                        std::iter::once(leg).inspect(|_| probes.set(probes.get() + 1)),
                    )
                };
                for leaf in (0..count).rev() {
                    let leg = Leg {
                        debit: true,
                        account: if many_cells { u128::from(leaf) } else { 0 },
                        unit: 1,
                        mantissa: 5,
                    };
                    assert_eq!(visibility(leaf, 100, &leg), Some(true));
                    assert_eq!(visibility(leaf + count, 100, &leg), Some(false));
                    assert_eq!(visibility(leaf, 101, &leg), None);
                    let other_unit = Leg { unit: 2, ..leg };
                    assert_eq!(visibility(leaf, 100, &other_unit), None);
                }
                assert_eq!(balance_visits.get(), if many_cells { count } else { 1 });
                assert_eq!(leaf_visits.get(), count);
                assert_eq!(probes.get(), 4 * count);
            }
        }
    }

    #[test]
    fn the_chart_is_exactly_the_declared_accounts() {
        let declared: BTreeMap<u128, crate::report::DeclaredAccount> = [
            ("1000", "Cash", 1, 0),
            ("4000", "Revenue", 4, 1),
            ("6000", "Rent", 5, 0),
        ]
        .into_iter()
        .zip(0u128..)
        .map(|((code, name, account_type, normal_balance), vid)| {
            (
                vid,
                crate::report::DeclaredAccount {
                    code: code.into(),
                    name: name.into(),
                    account_type,
                    normal_balance,
                    roles: Vec::new(),
                },
            )
        })
        .collect();
        let chart = format!(
            "{CHART_HEADER}\n1000|Cash|Asset|D\n4000|Revenue|Revenue|C\n6000|Rent|Expense|D\n"
        );
        assert_eq!(chart_rows(&chart, &declared, &[], None, false), Ok(3));
        for bad in [
            chart.replace("|Cash|", "|Petty cash|"),
            chart.replace("Revenue|C", "Revenue|D"),
            chart.replace("Rent|Expense", "Rent|Asset"),
            chart.replace("6000|Rent|Expense|D\n", ""),
            format!("{chart}9999|Extra|Asset|D\n"),
            chart.replace(CHART_HEADER, "GL_Account_Number|GL_Account_Name"),
        ] {
            assert!(
                chart_rows(&bad, &declared, &[], None, false).is_err(),
                "{bad}"
            );
        }
        // One account's extract: the accounts its rows and its scope name.
        let gl = format!(
            "{GL_HEADER}\n\
             aa|1|2026-03-10|7|1|1000|D|1.00|USD|2|x||\n\
             aa|2|2026-03-10|7|1|4000|C|1.00|USD|2|x||\n"
        );
        let extract = extracted(&gl, false, false).unwrap();
        let cash = format!("{CHART_HEADER}\n1000|Cash|Asset|D\n4000|Revenue|Revenue|C\n");
        assert_eq!(
            chart_rows(&cash, &declared, &extract, Some("1000"), false),
            Ok(2)
        );
        assert!(
            chart_rows(&chart, &declared, &extract, Some("1000"), false).is_err(),
            "an account the extract never names is not its chart"
        );
    }

    #[test]
    fn account_type_names_are_the_registered_ones() {
        let registry = include_str!("../../../registries/account_types.toml");
        let mut tags = Vec::new();
        let mut names = Vec::new();
        for line in registry.lines() {
            if let Some(tag) = line.strip_prefix("tag = ") {
                tags.push(tag.trim().parse::<usize>().unwrap());
            }
            if let Some(name) = line.strip_prefix("name = ") {
                names.push(name.trim().trim_matches('"').to_string());
            }
        }
        assert_eq!(tags, (1..=8).collect::<Vec<_>>());
        assert_eq!(names, ACCOUNT_TYPE_NAMES);
    }

    #[test]
    fn the_certificate_fields_read_as_written() {
        let cert = "schema_version = 1\neffective_through = \"2026-03-31\"\nknown_at_seq = 42\n";
        assert_eq!(field(cert, "effective_through"), Some("2026-03-31"));
        assert_eq!(field(cert, "known_at_seq"), Some("42"));
        assert_eq!(field(cert, "entry_count"), None);
        // A v3 certificate's account_scope_utf8_hex.
        assert_eq!(utf8_hex("31307c30").as_deref(), Some("10|0"));
        for bad in ["313", "3G", "31AB", "ff"] {
            assert_eq!(utf8_hex(bad), None, "{bad}");
        }
    }

    #[test]
    fn units_stay_one_to_one() {
        let mut units = Units::default();
        assert!(units.admits("USD", 1));
        units.by_code.insert("USD".into(), 1);
        units.by_id.insert(1, "USD".into());
        assert!(units.admits("USD", 1));
        assert!(!units.admits("USD", 2), "one code, two ids");
        assert!(!units.admits("EUR", 1), "two codes, one id");
        assert!(units.admits("EUR", 2));
    }
}
