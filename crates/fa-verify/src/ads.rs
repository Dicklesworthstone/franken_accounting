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

use std::collections::BTreeMap;

use crate::balance::CLASS_MIGRATION;
use crate::blake3::hash_parts;
use crate::bundle::{BundleError, BundleReport, BundleScope, civil, verify_bundle_observing};
use crate::envelope::{KIND_ENTRY, LeafEnvelope, Leg};

/// `EntryClass::PENDING`: a hold, never exported.
pub const CLASS_PENDING: u16 = 2;
/// The GL_Detail header `fa export ads` writes.
pub const GL_HEADER: &str = "Journal_ID|Journal_Entry_Line_Number|Effective_Date|Recorded_Seq|Entry_Class|GL_Account_Number|Debit_Credit_Indicator|Amount|Transaction_Currency|Unit_Scale|JE_Header_Description|Migrated_From|Line_Description";
const GL_FIELDS: usize = 13;
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
    /// Unit code to the unit id its rows matched, one to one.
    pub units: Vec<(String, u32)>,
    /// Every way the extract differs from the proven selection.
    pub failures: Vec<String>,
}

impl AdsReport {
    /// The bundle verified and the extract is exactly its selection.
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
}

/// What an extract states, read by its own format's reader: its coordinate,
/// entries, balances and chart. A part that does not read is its error.
pub(crate) struct Stated {
    pub(crate) effective_through: String,
    pub(crate) known_at_seq: Option<u64>,
    pub(crate) entry_count: Option<u64>,
    pub(crate) account_scope: Option<String>,
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
struct Proven {
    class: u16,
    date: String,
    legs: Vec<Leg>,
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

fn parse_row(line: &str, number: usize, escaped: bool) -> Result<Row, String> {
    let decoded = fields(line, escaped, true)?;
    let fields: Vec<&str> = decoded.iter().map(String::as_str).collect();
    if fields.len() != GL_FIELDS {
        return Err(format!(
            "GL_Detail line {number} has {} fields, not {GL_FIELDS} (a description holding a line break makes a row unreadable)",
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
    })
}

/// GL_Detail as entries, rows grouped by `Journal_ID` in first-seen order,
/// each numbered 1.. in order and agreeing on sequence, date and class.
fn extracted(gl_detail: &str, escaped: bool) -> Result<Vec<Extracted>, String> {
    let mut lines = gl_detail.split('\n');
    if lines.next() != Some(GL_HEADER) {
        return Err("GL_Detail does not start with the ADS GL header".to_string());
    }
    let mut order: Vec<String> = Vec::new();
    let mut by_id: BTreeMap<String, Extracted> = BTreeMap::new();
    for (i, line) in lines.enumerate() {
        if line.is_empty() {
            continue;
        }
        let row = parse_row(line, i.saturating_add(2), escaped)?;
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
fn same(extract: &Extracted, proven: &Proven, book: &[u8; 16], units: &Units) -> bool {
    extract.class == proven.class
        && extract.date == proven.date
        && extract.rows.len() == proven.legs.len()
        && extract.rows.iter().zip(&proven.legs).all(|(row, leg)| {
            account_vid(book, &row.account) == leg.account
                && row.debit == leg.debit
                && row.mantissa == leg.mantissa
                && units.admits(&row.unit, leg.unit)
        })
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
    let escaped = match field(certificate, "format") {
        Some("aicpa_ads_gl_v3") => true,
        Some("aicpa_ads_gl_v2") | None => false,
        Some(other) => {
            out.failures
                .push(format!("unsupported ADS format version {other:?}"));
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
    let stated = Stated {
        effective_through: out.effective_through.clone(),
        known_at_seq: out.known_at_seq,
        entry_count: field(certificate, "entry_count").and_then(|v| v.parse().ok()),
        account_scope: scoped,
        entries: extracted(gl_detail, escaped),
        balances: ads_balances(trial_balance, escaped),
        chart: ads_chart(chart_of_accounts, escaped),
    };
    Ok(judge(out, authenticated, stated, &ADS_PARTS))
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
    for (leaf, envelope, legs, _) in records {
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
            let read = balances
                .iter()
                .map(|balance| (&balance.claim, balance.contributing.as_slice()));
            match chunk_visibility(leaf, day, &legs, read) {
                Some(true) => {}
                // Its run hides it: the export selects it no more than the
                // fold does.
                Some(false) => continue,
                None => {
                    out.failures.push(format!(
                        "a migration chunk recorded at {} is in scope, and no verified balance over its cells proves whether its run makes it visible",
                        envelope.commit_seq
                    ));
                    continue;
                }
            }
        }
        proven.entry(envelope.commit_seq).or_default().push(Proven {
            class: envelope.class,
            date,
            legs,
        });
    }
    let extract = match stated.entries {
        Ok(extract) => extract,
        Err(why) => {
            out.failures.push(why);
            return out;
        }
    };
    let mut units = Units::default();
    for entry in &extract {
        let candidates = proven.get_mut(&entry.seq);
        let found = candidates.as_ref().and_then(|list| {
            list.iter()
                .position(|p| same(entry, p, &manifest.book_id, &units))
        });
        match (candidates, found) {
            (Some(list), Some(i)) => {
                let matched = list.remove(i);
                for (row, leg) in entry.rows.iter().zip(&matched.legs) {
                    units.by_code.insert(row.unit.clone(), leg.unit);
                    units.by_id.insert(leg.unit, row.unit.clone());
                }
                out.entries = out.entries.saturating_add(1);
                out.rows = out
                    .rows
                    .saturating_add(u64::try_from(entry.rows.len()).unwrap_or(u64::MAX));
            }
            _ => out.failures.push(format!(
                "{} {} (recorded at {}) is no proven entry selected through {cutoff}",
                parts.entry, entry.journal_id, entry.seq
            )),
        }
    }
    for (seq, list) in &proven {
        for p in list {
            out.failures.push(format!(
                "a proven entry recorded at {seq} (effective {}, {} legs) is missing from {}",
                p.date,
                p.legs.len(),
                parts.entries
            ));
        }
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
    out
}

/// Whether the migration chunk at `leaf`, effective on `day`, with `legs`
/// counts (fa-mv0f). A verified balance over one of its cells, cut off on or
/// after its day, decides that from the run bodies it carries, and only the
/// migration-aware format verifies such a cell: its fold reads the chunk
/// exactly when the chunk's run makes it visible. So the answer is
/// `Some(true)` when such a balance read it, `Some(false)` when such
/// balances exist and none read it (its run hides it), and `None` when none
/// covers it, so that its visibility is not proven.
fn chunk_visibility<'a>(
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
            && row.side == side;
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
        let entries = extracted(&gl, true).unwrap();
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
        let legacy = extracted(&gl, false).unwrap();
        assert_eq!(legacy[0].journal_id, r"entry\pid");
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
        let entries = extracted(&gl, false).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].rows.len(), 2);
        assert!(!entries[0].rows[1].debit);
        assert_eq!(entries[1].rows[0].mantissa, 100);

        let skipped = gl.replace("aa|2|", "aa|3|");
        assert!(extracted(&skipped, false).is_err(), "line 2 is missing");
        let torn = gl.replace("|Rent||\n", "|Ren\nt||\n");
        assert!(extracted(&torn, false).is_err(), "a broken row is refused");
        assert!(
            extracted("Journal_ID|x\n", false).is_err(),
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
        let extract = extracted(&gl, false).unwrap();
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
        let extract = extracted(&gl, false).unwrap();
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
