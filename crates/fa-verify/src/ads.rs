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
//! migration chunk in scope is not judged: its visibility is not proven
//! offline, as for balances. `Trial_Balance.txt` must then be exactly the
//! refold of those proven rows, so it is proven too; the chart's names and
//! types are not.

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
    /// GL_Detail entries and rows matched to proven entries.
    pub entries: u64,
    pub rows: u64,
    /// Trial_Balance rows equal to the refold of those rows.
    pub tb_rows: u64,
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

/// One GL_Detail row.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Row {
    journal_id: String,
    line: u32,
    date: String,
    seq: u64,
    class: u16,
    account: String,
    debit: bool,
    mantissa: i128,
    unit: String,
    scale: u32,
}

/// One extract entry: its rows in line order.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Extracted {
    journal_id: String,
    seq: u64,
    date: String,
    class: u16,
    rows: Vec<Row>,
}

/// One proven entry the export selects.
struct Proven {
    class: u16,
    date: String,
    legs: Vec<Leg>,
}

/// `value` at `scale` decimal places as an exact mantissa: digits, then a
/// point and exactly `scale` digits when `scale > 0`.
fn exact(value: &str, scale: u32) -> Option<i128> {
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
                if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
                    return Err("invalid ADS v3 control escape".into());
                }
                let scalar = u32::from_str_radix(&digits, 16).map_err(|_| "invalid ADS v3 scalar")?;
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
    line.split('|').enumerate().map(|(i, s)| {
        if escaped && gl && matches!(i, 11 | 12) && s == "\\N" {
            Ok(String::new())
        } else if escaped { decode_field(s) } else { Ok(s.into()) }
    }).collect()
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

/// Verify the bundle, then the extract against the entries it proves. The
/// bundle's own failure is reported, never masked; the extract is judged
/// only against a verified complete-prefix bundle.
pub fn verify_ads(
    certificate: &str,
    gl_detail: &str,
    trial_balance: &str,
    bundle: &[u8],
    trusted_keys: &[[u8; 32]],
    receipt: Option<&[u8]>,
) -> Result<AdsReport, BundleError> {
    let mut records: Vec<(LeafEnvelope, Vec<Leg>)> = Vec::new();
    let report = verify_bundle_observing(
        bundle,
        trusted_keys,
        receipt,
        |_, _| {},
        |envelope, legs| records.push((envelope.clone(), legs.to_vec())),
    )?;
    let mut out = AdsReport {
        bundle: report,
        effective_through: field(certificate, "effective_through")
            .unwrap_or_default()
            .to_string(),
        known_at_seq: field(certificate, "known_at_seq").and_then(|v| v.parse().ok()),
        entries: 0,
        rows: 0,
        tb_rows: 0,
        units: Vec::new(),
        failures: Vec::new(),
    };
    if !out.bundle.verified() {
        out.failures
            .push("the bundle did not verify, so GL_Detail was not judged against it".into());
        return Ok(out);
    }
    let escaped = match field(certificate, "format") {
        Some("aicpa_ads_gl_v3") => true,
        Some("aicpa_ads_gl_v2") | None => false,
        Some(other) => {
            out.failures.push(format!("unsupported ADS format version {other:?}"));
            return Ok(out);
        }
    };
    let manifest = out.bundle.manifest.clone();
    if !matches!(manifest.scope, BundleScope::Prefix) {
        out.failures.push(
            "the bundle proves a narrower scope; an ADS extract is judged against a complete-prefix bundle"
                .into(),
        );
        return Ok(out);
    }
    if out.known_at_seq != Some(manifest.through_seq) {
        out.failures.push(format!(
            "the certificate's known_at_seq ({}) is not the checkpoint's through_seq ({})",
            out.known_at_seq
                .map_or_else(|| "absent".to_string(), |s| s.to_string()),
            manifest.through_seq
        ));
        return Ok(out);
    }
    let cutoff = out.effective_through.clone();
    if cutoff.len() != 10 {
        out.failures
            .push("the certificate states no effective_through date".into());
        return Ok(out);
    }
    // The proven entries the export selects, by recorded sequence.
    let mut proven: BTreeMap<u64, Vec<Proven>> = BTreeMap::new();
    for (envelope, legs) in records {
        let Some(day) = envelope.effective_day else {
            continue;
        };
        let date = civil(day);
        if envelope.kind != KIND_ENTRY
            || envelope.class == CLASS_PENDING
            || legs.is_empty()
            || date > cutoff
        {
            continue;
        }
        if envelope.class == CLASS_MIGRATION {
            out.failures.push(format!(
                "a migration chunk recorded at {} is in scope; its visibility is not proven offline",
                envelope.commit_seq
            ));
            continue;
        }
        proven.entry(envelope.commit_seq).or_default().push(Proven {
            class: envelope.class,
            date,
            legs,
        });
    }
    let extract = match extracted(gl_detail, escaped) {
        Ok(extract) => extract,
        Err(why) => {
            out.failures.push(why);
            return Ok(out);
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
                "GL_Detail entry {} (recorded at {}) is no proven entry selected through {cutoff}",
                entry.journal_id, entry.seq
            )),
        }
    }
    for (seq, list) in &proven {
        for p in list {
            out.failures.push(format!(
                "a proven entry recorded at {seq} (effective {}, {} legs) is missing from GL_Detail",
                p.date,
                p.legs.len()
            ));
        }
    }
    let stated = field(certificate, "entry_count").and_then(|v| v.parse::<u64>().ok());
    if out.failures.is_empty() && stated != Some(out.entries) {
        out.failures.push(format!(
            "the certificate's entry_count ({}) is not the {} entries GL_Detail holds",
            stated.map_or_else(|| "absent".to_string(), |c| c.to_string()),
            out.entries
        ));
    }
    if out.failures.is_empty() {
        match trial_balance_rows(trial_balance, &extract, &cutoff, escaped) {
            Ok(rows) => out.tb_rows = rows,
            Err(why) => out.failures.push(why),
        }
    }
    out.units = units.by_code.into_iter().collect();
    Ok(out)
}

/// Check `trial_balance` is exactly the refold of the extract's rows: one
/// row per (account, currency) in that order, as of `cutoff`, the signed
/// sum of its legs (debits positive) stated as D (zero or more) or C with
/// its magnitude at the currency's one scale. Returns the row count.
fn trial_balance_rows(
    trial_balance: &str,
    extract: &[Extracted],
    cutoff: &str,
    escaped: bool,
) -> Result<u64, String> {
    let mut folded: BTreeMap<(&str, &str), (i128, u32)> = BTreeMap::new();
    for row in extract.iter().flat_map(|entry| &entry.rows) {
        let cell = folded
            .entry((row.account.as_str(), row.unit.as_str()))
            .or_insert((0, row.scale));
        if cell.1 != row.scale {
            return Err(format!("GL_Detail states two scales for {}", row.unit));
        }
        let moved = if row.debit {
            cell.0.checked_add(row.mantissa)
        } else {
            cell.0.checked_sub(row.mantissa)
        };
        cell.0 =
            moved.ok_or_else(|| "a GL_Detail balance exceeds the exact fold range".to_string())?;
    }
    let mut lines = trial_balance.split('\n');
    if lines.next() != Some(TB_HEADER) {
        return Err("Trial_Balance does not start with the ADS trial balance header".into());
    }
    let stated: Vec<&str> = lines.filter(|line| !line.is_empty()).collect();
    if stated.len() != folded.len() {
        return Err(format!(
            "Trial_Balance has {} rows; the proven GL_Detail folds to {} (account, currency) balances",
            stated.len(),
            folded.len()
        ));
    }
    for (line, ((account, unit), (balance, scale))) in stated.iter().zip(&folded) {
        let decoded = fields(line, escaped, false)?;
        let fields: Vec<&str> = decoded.iter().map(String::as_str).collect();
        let magnitude = balance
            .checked_abs()
            .ok_or_else(|| "a GL_Detail balance exceeds the exact fold range".to_string())?;
        let side = if *balance < 0 { "C" } else { "D" };
        let agrees = fields.len() == 6
            && fields[0] == *account
            && fields[1] == cutoff
            && fields[2] == side
            && fields[5].parse::<u32>().ok() == Some(*scale)
            && exact(fields[3], *scale) == Some(magnitude)
            && fields[4] == *unit;
        if !agrees {
            return Err(format!(
                "Trial_Balance row `{line}` is not the refold of the proven GL_Detail ({account} {unit}: {side} {magnitude} at scale {scale}, as of {cutoff})"
            ));
        }
    }
    u64::try_from(stated.len()).map_err(|_| "Trial_Balance row count".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(extracted("Journal_ID|x\n", false).is_err(), "not the ADS header");
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
        assert_eq!(trial_balance_rows(&tb, &extract, "2026-03-31", false), Ok(3));
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
                trial_balance_rows(&bad, &extract, "2026-03-31", false).is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn the_certificate_fields_read_as_written() {
        let cert = "schema_version = 1\neffective_through = \"2026-03-31\"\nknown_at_seq = 42\n";
        assert_eq!(field(cert, "effective_through"), Some("2026-03-31"));
        assert_eq!(field(cert, "known_at_seq"), Some("42"));
        assert_eq!(field(cert, "entry_count"), None);
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
