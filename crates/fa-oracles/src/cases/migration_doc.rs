//! A migration variant's declared legacy trial balance
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §6.6; bead fa-yugf.18, A7m).
//!
//! `fa migrate open` takes a trial balance document and, for a sole-source
//! FullDetail run, one cumulative trial balance per elapsed Historical
//! period; `fa migrate finalize` refuses `FA-REF-131` unless the staged
//! chunks fold to every one of them. A case has no legacy ledger, so the
//! trial balance is the registered `legacy_tb_from_chunks` rule over the
//! variant's legacy history: every Migration intent it declares. A book
//! stages all of them, so the tie-out is tautological and supports no
//! claim; a legacy entry left unstaged is what finalize catches.
//!
//! The document is a reconstruction (`stub_of = "legacy_tb"`), never a
//! source: `fa:case-legacy-tb:v1`, `rule=legacy_tb_from_chunks`, then one
//! `<period>\t<account>\t<unit>\t<amount>` line per declared line, the
//! amount signed debit-positive at the unit's scale. It names no fact.

use core::fmt;
use std::collections::BTreeMap;

use super::amount::{AmountError, format_amount, parse_amount};
use super::book::BookVariant;
use super::derive::{DeriveError, Rules};

/// The document's first line; a change to the layout is a new tag.
pub const FORMAT: &str = "fa:case-legacy-tb:v1";

/// The registered derivation rule the trial balance is.
pub const RULE: &str = "legacy_tb_from_chunks";

/// One declared line: the cumulative balance of `account` in `unit`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TbLine {
    pub account: String,
    pub unit: String,
    /// Debit-positive, in minor units.
    pub minor: i128,
    /// The unit's registered scale.
    pub scale: u8,
}

impl TbLine {
    /// The signed amount at the unit's scale.
    #[must_use]
    pub fn amount(&self) -> String {
        format_amount(self.minor, self.scale)
    }

    /// The magnitude at the unit's scale, for a `debit` or `credit` field.
    #[must_use]
    pub fn magnitude(&self) -> String {
        format_amount(self.minor.saturating_abs(), self.scale)
    }
}

/// One Historical period's cumulative trial balance, by period label.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodTb {
    pub period: String,
    pub lines: Vec<TbLine>,
}

/// Why a variant has no declarable legacy trial balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LegacyTbError {
    /// The variant declares no Historical `[[period]]`.
    NoHistoricalPeriod,
    /// The variant declares no Migration intent.
    NoChunk,
    /// A leg's unit is not a registered unit.
    UnknownUnit(String),
    /// A leg's amount does not parse at its unit's scale.
    Amount { intent: String, error: AmountError },
    /// A leg's side is not `Dr` or `Cr`.
    Side { intent: String, side: String },
    /// The derivation registry did not load or lacks the rule.
    Rules(String),
    /// The rule refused its inputs.
    Derive(DeriveError),
    /// A period's lines break `fa migrate open`'s shape rules.
    Shape { period: String, detail: String },
}

impl fmt::Display for LegacyTbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHistoricalPeriod => f.write_str("the variant declares no Historical period"),
            Self::NoChunk => f.write_str("the variant declares no Migration intent"),
            Self::UnknownUnit(unit) => write!(f, "`{unit}` is not a registered unit"),
            Self::Amount { intent, error } => write!(f, "intent {intent}: {error}"),
            Self::Side { intent, side } => {
                write!(f, "intent {intent}: leg side `{side}` is Dr or Cr")
            }
            Self::Rules(why) => write!(f, "{RULE}: {why}"),
            Self::Derive(error) => write!(f, "{RULE}: {error}"),
            Self::Shape { period, detail } => write!(f, "period {period}: {detail}"),
        }
    }
}

impl core::error::Error for LegacyTbError {}

fn scale_of(unit: &str) -> Result<u8, LegacyTbError> {
    fa_registry::units_embedded()
        .ok()
        .and_then(|units| units.into_iter().find(|u| u.code == unit))
        .map(|u| u.scale)
        .ok_or_else(|| LegacyTbError::UnknownUnit(unit.to_string()))
}

/// The declared trial balance of `book`: for each Historical period in
/// calendar order, the cumulative fold of every Migration intent's legs
/// dated through its last day, zero lines omitted, in (account, unit)
/// order.
///
/// # Errors
///
/// [`LegacyTbError`] naming why.
pub fn legacy_tb(book: &BookVariant) -> Result<Vec<PeriodTb>, LegacyTbError> {
    let mut periods: Vec<_> = book
        .periods
        .iter()
        .filter(|p| p.kind == "Historical")
        .collect();
    if periods.is_empty() {
        return Err(LegacyTbError::NoHistoricalPeriod);
    }
    periods.sort_by(|a, b| a.start.cmp(&b.start));
    let mut scales: BTreeMap<String, u8> = BTreeMap::new();
    let mut inputs = Vec::new();
    for it in book.intents.iter().filter(|i| i.class == "Migration") {
        for l in book.legs.iter().filter(|l| l.intent == it.id) {
            let scale = match scales.get(&l.unit) {
                Some(s) => *s,
                None => {
                    let s = scale_of(&l.unit)?;
                    scales.insert(l.unit.clone(), s);
                    s
                }
            };
            let amount = |error| LegacyTbError::Amount {
                intent: it.id.clone(),
                error,
            };
            let minor = parse_amount(&l.amount_literal, scale).map_err(amount)?;
            let signed = match l.side.as_str() {
                "Dr" => minor,
                "Cr" => minor
                    .checked_neg()
                    .ok_or_else(|| amount(AmountError::Overflow))?,
                other => {
                    return Err(LegacyTbError::Side {
                        intent: it.id.clone(),
                        side: other.to_string(),
                    });
                }
            };
            inputs.push(format!(
                "{}|{}|{}|{signed}",
                it.effective_date, l.account, l.unit
            ));
        }
    }
    if inputs.is_empty() {
        return Err(LegacyTbError::NoChunk);
    }
    let rules = Rules::embedded()
        .map_err(|e| LegacyTbError::Rules(format!("{} load error(s)", e.len())))?;
    let rule = rules
        .get(RULE)
        .ok_or_else(|| LegacyTbError::Rules("not a registered rule".into()))?;
    let declared: Vec<String> = periods
        .iter()
        .map(|p| format!("{}@{}", p.code, p.end))
        .collect();
    let params = rules
        .params(rule, &[format!("periods={}", declared.join(","))])
        .map_err(LegacyTbError::Derive)?;
    let folded = rules
        .evaluate(RULE, &params, &inputs)
        .map_err(LegacyTbError::Derive)?;
    let mut out = Vec::new();
    for part in folded.split(';') {
        let shape = |detail: String| LegacyTbError::Shape {
            period: part.to_string(),
            detail,
        };
        let (label, lines) = part
            .split_once('=')
            .ok_or_else(|| shape("the rule's output is not `<period>=<lines>`".into()))?;
        let mut parsed = Vec::new();
        for line in lines.split(',').filter(|l| !l.is_empty()) {
            let mut fields = line.splitn(3, ':');
            let (Some(account), Some(unit), Some(value)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(shape(format!("`{line}` is not `<account>:<unit>:<minor>`")));
            };
            let minor = value
                .parse::<i128>()
                .map_err(|_| shape(format!("`{value}` is not an integer")))?;
            let scale = scale_of(unit)?;
            parsed.push(TbLine {
                account: account.to_string(),
                unit: unit.to_string(),
                minor,
                scale,
            });
        }
        out.push(PeriodTb {
            period: label.to_string(),
            lines: parsed,
        });
    }
    Ok(out)
}

/// `fa migrate open`'s shape rules for declared lines
/// (crates/fa-journal/src/migration.rs `check_lines`): each period has a
/// line, lines strictly ascend by (account, unit), none is zero, and every
/// unit nets to zero.
///
/// # Errors
///
/// [`LegacyTbError::Shape`] naming the period and the broken rule.
pub fn check_shape(tb: &[PeriodTb]) -> Result<(), LegacyTbError> {
    for p in tb {
        let shape = |detail: String| LegacyTbError::Shape {
            period: p.period.clone(),
            detail,
        };
        if p.lines.is_empty() {
            return Err(shape("declares no line".into()));
        }
        let mut net: BTreeMap<&str, i128> = BTreeMap::new();
        for (i, l) in p.lines.iter().enumerate() {
            if l.minor == 0 {
                return Err(shape(format!("{} {} is zero", l.account, l.unit)));
            }
            if let Some(prev) = i.checked_sub(1).and_then(|j| p.lines.get(j))
                && (prev.account.as_str(), prev.unit.as_str())
                    >= (l.account.as_str(), l.unit.as_str())
            {
                return Err(shape(format!(
                    "{} {} does not follow {} {} in (account, unit) order",
                    l.account, l.unit, prev.account, prev.unit
                )));
            }
            let slot = net.entry(l.unit.as_str()).or_default();
            *slot = slot
                .checked_add(l.minor)
                .ok_or_else(|| shape("a unit's net overflows i128".into()))?;
        }
        if let Some((unit, v)) = net.iter().find(|(_, v)| **v != 0) {
            return Err(shape(format!("{unit} nets to {v} minor units")));
        }
    }
    Ok(())
}

/// The document's bytes for `tb`, refused before rendering when a period
/// breaks [`check_shape`].
///
/// # Errors
///
/// [`LegacyTbError::Shape`].
pub fn render(tb: &[PeriodTb]) -> Result<Vec<u8>, LegacyTbError> {
    check_shape(tb)?;
    let mut out = format!("{FORMAT}\nrule={RULE}\n");
    for p in tb {
        for l in &p.lines {
            out.push_str(&p.period);
            for field in [l.account.as_str(), l.unit.as_str(), l.amount().as_str()] {
                out.push('\t');
                out.push_str(field);
            }
            out.push('\n');
        }
    }
    Ok(out.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cases::CASE_EXTENSIONS;
    use crate::cases::tests::{Files, load_files};

    const MIGRATION_RUN: [(&str, &str); 5] = [
        (
            "case.toml",
            include_str!("../../tests/fixtures/migration_run/case.toml"),
        ),
        (
            "roles.toml",
            include_str!("../../tests/fixtures/migration_run/roles.toml"),
        ),
        (
            "facts.toml",
            include_str!("../../tests/fixtures/migration_run/facts.toml"),
        ),
        (
            "books/migration.toml",
            include_str!("../../tests/fixtures/migration_run/books/migration.toml"),
        ),
        (
            "expectations.toml",
            include_str!("../../tests/fixtures/migration_run/expectations.toml"),
        ),
    ];

    fn line(account: &str, minor: i128) -> TbLine {
        TbLine {
            account: account.into(),
            unit: "USD".into(),
            minor,
            scale: 2,
        }
    }

    #[test]
    fn legacy_tb_document_bytes_rerender_identically_and_name_no_fact() {
        let files: Files = MIGRATION_RUN
            .iter()
            .map(|(p, t)| (*p, (*t).to_string()))
            .collect();
        let case = load_files("migration_run", &files, CASE_EXTENSIONS)
            .expect("the migration run fixture loads");
        let book = &case.books["migration"];
        let tb = legacy_tb(book).expect("the fixture's chunks fold");
        let bytes = render(&tb).expect("renders");
        assert_eq!(
            String::from_utf8(bytes.clone()).expect("utf-8"),
            "fa:case-legacy-tb:v1\nrule=legacy_tb_from_chunks\n\
             2001Q3\t1530\tUSD\t544000000.00\n2001Q3\t2110\tUSD\t-544000000.00\n\
             2001Q4\t1530\tUSD\t544000000.00\n2001Q4\t2110\tUSD\t-544000000.00\n",
            "each Historical period's cumulative fold, through its last day"
        );
        assert_eq!(
            render(&legacy_tb(book).expect("again")).expect("again"),
            bytes,
            "a pure function of the chunks"
        );
        let text = String::from_utf8(bytes).expect("utf-8");
        for f in &case.facts {
            assert!(!text.contains(f.id.as_str()), "names fact {}", f.id);
        }
        check_shape(&tb).expect("every declared period passes check_lines' shape");
    }

    #[test]
    fn a_zero_or_out_of_order_line_is_refused_before_rendering() {
        let zero = [PeriodTb {
            period: "2001Q3".into(),
            lines: vec![line("1530", 0), line("2110", 0)],
        }];
        assert!(matches!(
            render(&zero),
            Err(LegacyTbError::Shape { detail, .. }) if detail == "1530 USD is zero"
        ));
        let backwards = [PeriodTb {
            period: "2001Q3".into(),
            lines: vec![line("2110", -5), line("1530", 5)],
        }];
        assert!(matches!(
            render(&backwards),
            Err(LegacyTbError::Shape { detail, .. })
                if detail == "1530 USD does not follow 2110 USD in (account, unit) order"
        ));
        let unbalanced = [PeriodTb {
            period: "2001Q3".into(),
            lines: vec![line("1530", 5), line("2110", -4)],
        }];
        assert!(matches!(
            render(&unbalanced),
            Err(LegacyTbError::Shape { detail, .. }) if detail == "USD nets to 1 minor units"
        ));
        let empty = [PeriodTb {
            period: "2001Q3".into(),
            lines: Vec::new(),
        }];
        assert!(render(&empty).is_err(), "a period declares a line");
    }
}
