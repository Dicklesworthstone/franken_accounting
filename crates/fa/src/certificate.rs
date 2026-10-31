//! Retained-history certificates for literal accounting reports (§13.6).
//!
//! Every certificate fixes the selector, native read closure, accounting journal
//! prefix, registry versions and exact report bytes. Native reads include the
//! chart, calendar, periods and migration state: an entry accumulator alone does
//! not authenticate those inputs. Replay verifies each native input against the
//! retained historical snapshot before refolding, and also detects a later
//! rewrite or retirement of an entry in that prefix.
//!
//! This is the explicit embedded-owner, `fa-fold-over-prefix` posture. It is a
//! local replay certificate, without a witness signature or a scoped outsider
//! completeness claim. The caller may retain its canonical, content-addressed
//! bytes without appending a write to the book being reported on.

use std::collections::{BTreeMap, BTreeSet};

use asupersync::fs::Vfs;
use fa_journal::genesis::{BookContext, BookSpec};
use fa_journal::refusal::{Refusal, exit};
use fa_journal::rows::{AccountRow, book_root, bytes, int, text};
use fa_model::symbols::{label, property};
use fa_model::{ControlPayload, Entry, EntryClass, EntryOrigin, Id128, Reader, Writer};
use fa_notary::journal::Journal;
use fa_registers::open_items::{OpenItemsReport, carries_open_items, open_items_report};
use fa_registers::{BalanceExplanation, TrialBalance};
use fa_time::DateDay;
use fgdb::{Database, NativeResultCertificate};
use fgdb_crypto::{Digest, Hasher};
use fgdb_delta_types::DeltaRow;
use fgdb_gql::{GqlParameters, GqlQueryPolicy};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, QueryCx, VId};

use crate::{BookError, Outcome};

mod functional;
pub(crate) use functional::verify_sources as verify_functional_sources;
pub(crate) mod case_status;
pub(crate) mod registry_epoch;

pub mod code {
    pub const CERTIFICATE_INVALID: &str = "FA-REF-150";
    pub const CERTIFICATE_REGISTRY_UNAVAILABLE: &str = "FA-REF-159";
}

pub const CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v1";
/// Instant-selected certificates extend the retained format with tick evidence.
pub const INSTANT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v2";
/// Additional literal reports use v3; v1/v2 trial-balance bytes stay unchanged.
pub const REPORT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v3";
/// Statements bind their complete canonical definition and comparative columns.
pub const STATEMENT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v4";
/// Functional statements additionally bind retained Rate documents and FX laws.
/// Existing native statements keep their v4 encoding and valuation semantics.
pub const FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v5";
pub const FUNCTIONAL_STATEMENT_OUTPUT_FORMAT: &str = "fa:functional-statement:v1";
/// A consolidation run of a multi-entity book (fa-76hy): one more selector
/// tag in its own format version, so earlier certificates keep their bytes.
pub const CONSOLIDATION_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v6";
pub const CONSOLIDATION_OUTPUT_FORMAT: &str = "fa:consolidation:v1";
/// A consolidation in the book's functional currency, with retained FX evidence.
/// Native v6 consolidation bytes and valuation semantics remain unchanged.
pub const FUNCTIONAL_CONSOLIDATION_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v7";
pub const FUNCTIONAL_CONSOLIDATION_OUTPUT_FORMAT: &str = "fa:functional-consolidation:v1";
/// A trial balance over only the legs one dimension value or a value under
/// it tags (fa-ficc). It also binds that dimension's values, whose parents
/// decide which values it folds.
pub const DIMENSION_TRIAL_BALANCE_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v8";
pub const DIMENSION_TRIAL_BALANCE_OUTPUT_FORMAT: &str = "fa:dimension-trial-balance:v1";
/// A regulatory schedule (plan §12.6, fa-doa9): the complete schedule (form,
/// schedule code, instruction version, its definition, which maps the chart
/// by account code, and its declared Instrument inputs) and its period
/// columns, with the statement it evaluates to. Native units only.
pub const REGULATORY_SCHEDULE_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v9";
pub const REGULATORY_SCHEDULE_OUTPUT_FORMAT: &str = "fa:regulatory-schedule:v1";
/// Functional trial balances retain entity cells, the historical display chart,
/// and the same independently replayed Rate/law closure as functional statements.
pub const FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v10";
pub const FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT: &str = "fa:functional-trial-balance:v1";
/// Approved company layouts, including explicit presentation rounding.
pub const CUSTOM_STATEMENT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v11";
/// The same approved custom layout evaluated from retained base valuations.
/// Native custom v11 bytes and meanings remain unchanged.
pub const FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT: &[u8] = b"fa:report-certificate:v12";
pub const REPLAY_SCOPE: &str = "fa-fold-over-prefix";
pub const AUTHORITY: &str = "embedded-owner";
pub const OUTPUT_FORMAT: &str = "fa:trial-balance:v1";
pub const MAX_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_PERIODS: usize = 65_536;
const MAX_NATIVE_BYTES: usize = 1024 * 1024;
// Definition at report known-at, approvals and policy at activation, and
// chart mirrors plus BookSpec immediately before the reviewed activation.
const CUSTOM_STATEMENT_INPUTS: usize = 5;

// These are the authoritative vertex families shared by literal report folds.
// Functional statements additionally bind the Rate-only Document projection.
// No Leg/Register mirror supplies a report's accounting facts. Every
// property decoded by AccountRow, PeriodRow and migration::run_from_row is
// included, even where a field currently only participates in validation.
const INPUTS: &[(&str, &str)] = &[
    (
        "Account",
        "code,name,account_type,normal_balance,posting,unit_policy,lower_bound,upper_bound,limit_scope,_fa_payload,book_id",
    ),
    (
        "Book",
        "_fa_payload,book_id,base_unit,symbols_digest,unit_table_digest",
    ),
    ("Entry", "_fa_payload,_fa_digest"),
    ("FiscalCalendar", "_fa_payload,calendar_id"),
    ("MigrationRun", "_fa_payload,_fa_digest,state"),
    (
        "Period",
        "code,calendar_id,fiscal_year,ordinal,period_kind,period_start,period_end,state",
    ),
    ("Unit", "_fa_payload,unit_id,code,name,scale,version"),
];

/// A stock trial balance by period cutoff/date, or explicit period activity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrialBalanceSelection {
    Periods(Vec<String>),
    AsOf(DateDay),
    Activity(Vec<String>),
}

impl TrialBalanceSelection {
    fn is_canonical(&self) -> bool {
        match self {
            Self::Periods(periods) | Self::Activity(periods) => {
                !periods.is_empty()
                    && periods.len() <= MAX_PERIODS
                    && periods
                        .iter()
                        .all(|period| !period.is_empty() && period.len() <= 128)
                    && periods.windows(2).all(|pair| pair[0] < pair[1])
            }
            Self::AsOf(_) => true,
        }
    }

    fn normalize(mut self) -> Self {
        if let Self::Periods(periods) | Self::Activity(periods) = &mut self {
            periods.sort();
            periods.dedup();
        }
        self
    }

    pub(crate) fn write(&self, w: &mut Writer) {
        match self {
            Self::Periods(periods) | Self::Activity(periods) => {
                w.u8(if matches!(self, Self::Periods(_)) {
                    0
                } else {
                    2
                })
                .list(periods, |w, p| {
                    w.str(p);
                });
            }
            Self::AsOf(day) => {
                w.u8(1).i32(day.0);
            }
        }
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        let tag = r.u8("report selector")?;
        match tag {
            0 | 2 => {
                let count = r.count(MAX_PERIODS, "selected periods")?;
                let mut periods = Vec::new();
                for _ in 0..count {
                    periods.push(r.str(128, "period code")?.to_string());
                }
                if periods.is_empty()
                    || periods.iter().any(String::is_empty)
                    || !periods.windows(2).all(|pair| pair[0] < pair[1])
                {
                    return Err(r.invalid("canonical nonempty period selection"));
                }
                Ok(if tag == 0 {
                    Self::Periods(periods)
                } else {
                    Self::Activity(periods)
                })
            }
            1 => Ok(Self::AsOf(DateDay(r.i32("as-of date")?))),
            _ => Err(r.bad_tag("report selector", tag)),
        }
    }

    pub(crate) fn report<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        book: &BookContext,
        at: CommitSeq,
    ) -> Result<TrialBalance, BookError> {
        Ok(match self {
            Self::Periods(periods) => fa_registers::trial_balance_at(db, book, periods, Some(at))?,
            Self::AsOf(day) => fa_registers::balance_as_of(db, book, *day, Some(at))?,
            Self::Activity(periods) => fa_registers::period_activity(db, book, periods, Some(at))?,
        })
    }
}

/// A literal accounting report with one fixed known-at coordinate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportSelection {
    TrialBalance(TrialBalanceSelection),
    /// Functional stock through one period or date, or one period's activity.
    /// Committed base valuations are replayed against their retained Rate laws.
    FunctionalTrialBalance(TrialBalanceSelection),
    ExplainBalance {
        account: VId,
        period: String,
    },
    OpenItems {
        account: Option<VId>,
    },
    Statement(Box<crate::StatementSelection>),
    /// The book's functional unit, using independently verified retained base
    /// valuations. No current-rate conversion or presentation translation.
    FunctionalStatement(Box<crate::StatementSelection>),
    /// The consolidation of the book's legal entities for one period (plan §12.3).
    Consolidation {
        period: String,
    },
    /// Group stock and activity in the shared functional unit, from verified
    /// retained base amounts. No current-rate translation is performed.
    FunctionalConsolidation {
        period: String,
    },
    /// `selection` over only the legs tagged with `dimension`'s `value` or
    /// a value under it (`fa tb --dimension`); the other legs of a tagged
    /// entry are left out, so it need not balance.
    DimensionTrialBalance {
        selection: TrialBalanceSelection,
        dimension: String,
        value: String,
    },
    /// A regulatory schedule over the same exact folds a statement of its
    /// kind uses, mapped by account code (`fa statement regulatory`).
    RegulatorySchedule(Box<crate::statements::RegulatorySelection>),
    CustomStatement(Box<crate::custom_statement::CustomStatementSelection>),
}

impl From<TrialBalanceSelection> for ReportSelection {
    fn from(selection: TrialBalanceSelection) -> Self {
        Self::TrialBalance(selection)
    }
}

impl From<crate::StatementSelection> for ReportSelection {
    fn from(selection: crate::StatementSelection) -> Self {
        Self::Statement(Box::new(selection))
    }
}

impl ReportSelection {
    fn is_canonical(&self) -> bool {
        match self {
            Self::TrialBalance(selection) => selection.is_canonical(),
            Self::FunctionalTrialBalance(selection) => {
                selection.is_canonical()
                    && crate::functional_trial_balance::supported_selection(selection)
            }
            Self::ExplainBalance { period, .. } => !period.is_empty() && period.len() <= 128,
            Self::OpenItems { .. } => true,
            Self::Statement(selection) | Self::FunctionalStatement(selection) => {
                selection.is_canonical()
            }
            Self::Consolidation { period } | Self::FunctionalConsolidation { period } => {
                !period.is_empty() && period.len() <= 128
            }
            Self::DimensionTrialBalance {
                selection,
                dimension,
                value,
            } => {
                selection.is_canonical()
                    && fa_model::dimension_kind(dimension).is_some()
                    && !value.is_empty()
                    && value.len() <= fa_model::rea::MAX_REA_CODE_BYTES
            }
            Self::RegulatorySchedule(selection) => selection.is_canonical(),
            Self::CustomStatement(selection) => selection.is_canonical(),
        }
    }

    /// The statement kind, period columns and comparative columns of a
    /// statement-shaped report: a native or functional statement, or a
    /// regulatory schedule. Each column folds the same way for all three.
    pub(crate) fn statement_columns(
        &self,
    ) -> Option<(fa_statements::StatementKind, &[String], &[String])> {
        match self {
            Self::Statement(selection) | Self::FunctionalStatement(selection) => Some((
                selection.definition.kind(),
                selection.periods.as_slice(),
                selection.comparative.as_slice(),
            )),
            Self::RegulatorySchedule(selection) => Some((
                selection.schedule.statement_definition.kind,
                selection.periods.as_slice(),
                selection.comparative.as_slice(),
            )),
            Self::CustomStatement(selection) => Some((
                selection.definition.kind,
                selection.periods.as_slice(),
                selection.comparative.as_slice(),
            )),
            _ => None,
        }
    }

    fn normalize(self) -> Self {
        match self {
            Self::TrialBalance(selection) => Self::TrialBalance(selection.normalize()),
            Self::FunctionalTrialBalance(selection) => {
                Self::FunctionalTrialBalance(selection.normalize())
            }
            Self::DimensionTrialBalance {
                selection,
                dimension,
                value,
            } => Self::DimensionTrialBalance {
                selection: selection.normalize(),
                dimension,
                value,
            },
            Self::Statement(selection) => Self::Statement(Box::new((*selection).normalize())),
            Self::FunctionalStatement(selection) => {
                Self::FunctionalStatement(Box::new((*selection).normalize()))
            }
            Self::RegulatorySchedule(selection) => {
                Self::RegulatorySchedule(Box::new((*selection).normalize()))
            }
            Self::CustomStatement(selection) => {
                Self::CustomStatement(Box::new((*selection).normalize()))
            }
            selection => selection,
        }
    }

    /// Functional reports require the retained Rate documents and complete
    /// Entry creation history used to verify each immutable base valuation.
    #[must_use]
    pub const fn uses_functional_valuations(&self) -> bool {
        match self {
            Self::FunctionalStatement(_)
            | Self::FunctionalConsolidation { .. }
            | Self::FunctionalTrialBalance(_) => true,
            Self::CustomStatement(selection) => selection.functional,
            _ => false,
        }
    }

    #[must_use]
    pub const fn output_format(&self) -> &'static str {
        match self {
            Self::TrialBalance(_) => OUTPUT_FORMAT,
            Self::FunctionalTrialBalance(_) => FUNCTIONAL_TRIAL_BALANCE_OUTPUT_FORMAT,
            Self::ExplainBalance { .. } => "fa:balance-explanation:v1",
            Self::OpenItems { .. } => "fa:open-items:v1",
            Self::Statement(_) => "fa:statement:v1",
            Self::FunctionalStatement(_) => FUNCTIONAL_STATEMENT_OUTPUT_FORMAT,
            Self::Consolidation { .. } => CONSOLIDATION_OUTPUT_FORMAT,
            Self::FunctionalConsolidation { .. } => FUNCTIONAL_CONSOLIDATION_OUTPUT_FORMAT,
            Self::DimensionTrialBalance { .. } => DIMENSION_TRIAL_BALANCE_OUTPUT_FORMAT,
            Self::RegulatorySchedule(_) => REGULATORY_SCHEDULE_OUTPUT_FORMAT,
            Self::CustomStatement(selection) if selection.functional => {
                crate::custom_statement::FUNCTIONAL_OUTPUT_FORMAT
            }
            Self::CustomStatement(_) => crate::custom_statement::OUTPUT_FORMAT,
        }
    }

    /// The registered dimension whose values a dimension-filtered report
    /// binds as one more native input.
    fn bound_dimension(&self) -> Option<fa_model::DimensionKind> {
        match self {
            Self::DimensionTrialBalance { dimension, .. } => fa_model::dimension_kind(dimension),
            _ => None,
        }
    }

    fn write(&self, w: &mut Writer) -> Result<(), fa_model::EncodeError> {
        match self {
            // V1 and V2 retain the original selector bytes without a new tag.
            Self::TrialBalance(selection) => selection.write(w),
            Self::FunctionalTrialBalance(selection) => {
                w.u8(8);
                selection.write(w);
            }
            Self::ExplainBalance { account, period } => {
                w.u8(0).u128(account.0).str(period);
            }
            Self::OpenItems { account } => {
                w.u8(1).opt(account.as_ref(), |w, vid| {
                    w.u128(vid.0);
                });
            }
            Self::Statement(selection) => {
                w.u8(2);
                selection.write(w)?;
            }
            Self::FunctionalStatement(selection) => {
                w.u8(3);
                selection.write(w)?;
            }
            Self::Consolidation { period } => {
                w.u8(4).str(period);
            }
            Self::FunctionalConsolidation { period } => {
                w.u8(5).str(period);
            }
            Self::DimensionTrialBalance {
                selection,
                dimension,
                value,
            } => {
                w.u8(6);
                selection.write(w);
                w.str(dimension).str(value);
            }
            Self::RegulatorySchedule(selection) => {
                w.u8(7);
                selection.write(w)?;
            }
            Self::CustomStatement(selection) => {
                w.u8(if selection.functional { 10 } else { 9 });
                selection.write(w)?;
            }
        }
        Ok(())
    }

    fn read(r: &mut Reader<'_>, version: u8) -> Result<Self, fa_model::DecodeError> {
        if version < 3 {
            return TrialBalanceSelection::read(r).map(Self::TrialBalance);
        }
        match r.u8("report selector")? {
            0 if version == 3 => Ok(Self::ExplainBalance {
                account: VId(r.u128("explanation account")?),
                period: r.str(128, "explanation period")?.to_string(),
            }),
            1 if version == 3 => Ok(Self::OpenItems {
                account: r.opt("open-items account", |r| Ok(VId(r.u128("account")?)))?,
            }),
            2 if version == 4 => Ok(Self::Statement(Box::new(crate::StatementSelection::read(
                r,
            )?))),
            3 if version == 5 => Ok(Self::FunctionalStatement(Box::new(
                crate::StatementSelection::read(r)?,
            ))),
            4 if version == 6 => Ok(Self::Consolidation {
                period: r.str(128, "consolidation period")?.to_string(),
            }),
            5 if version == 7 => Ok(Self::FunctionalConsolidation {
                period: r.str(128, "functional consolidation period")?.to_string(),
            }),
            6 if version == 8 => Ok(Self::DimensionTrialBalance {
                selection: TrialBalanceSelection::read(r)?,
                dimension: r
                    .str(fa_model::rea::MAX_REA_CODE_BYTES, "report dimension")?
                    .to_string(),
                value: r
                    .str(fa_model::rea::MAX_REA_CODE_BYTES, "report dimension value")?
                    .to_string(),
            }),
            7 if version == 9 => Ok(Self::RegulatorySchedule(Box::new(
                crate::statements::RegulatorySelection::read(r)?,
            ))),
            8 if version == 10 => Ok(Self::FunctionalTrialBalance(TrialBalanceSelection::read(
                r,
            )?)),
            9 if version == 11 => Ok(Self::CustomStatement(Box::new(
                crate::custom_statement::CustomStatementSelection::read(r, false)?,
            ))),
            10 if version == 12 => Ok(Self::CustomStatement(Box::new(
                crate::custom_statement::CustomStatementSelection::read(r, true)?,
            ))),
            tag => Err(r.bad_tag("report selector", tag)),
        }
    }

    fn report<V: Vfs + Clone>(
        &self,
        db: &Database<V>,
        cx: &QueryCx,
        book: &BookContext,
        at: CommitSeq,
    ) -> Outcome<ReportOutput> {
        match self {
            Self::TrialBalance(selection) => Ok(Ok(ReportOutput::TrialBalance(
                selection.report(db, book, at)?,
            ))),
            Self::FunctionalTrialBalance(selection) => Ok(
                crate::functional_trial_balance::report_at(db, book, selection, at)?
                    .map(|report| ReportOutput::FunctionalTrialBalance(Box::new(report))),
            ),
            Self::ExplainBalance { account, period } => {
                Ok(Ok(ReportOutput::ExplainBalance(Box::new(
                    fa_registers::explain_balance(db, book, *account, period, Some(at))?,
                ))))
            }
            Self::OpenItems { account } => Ok(Ok(ReportOutput::OpenItems(open_items_report(
                db,
                book,
                *account,
                Some(at),
            )?))),
            Self::Statement(selection) => {
                Ok(crate::statements::report_at(db, book, selection, at)?
                    .map(|statement| ReportOutput::Statement(Box::new(statement))))
            }
            Self::FunctionalStatement(selection) => Ok(crate::statements::report_functional_at(
                db, book, selection, at,
            )?
            .map(|statement| ReportOutput::FunctionalStatement(Box::new(statement)))),
            Self::Consolidation { period } => {
                Ok(crate::consolidation::consolidate_at(db, book, period, at)?
                    .map(|run| ReportOutput::Consolidation(Box::new(run))))
            }
            Self::FunctionalConsolidation { period } => Ok(
                crate::consolidation::consolidate_functional_at(db, book, period, at)?
                    .map(|run| ReportOutput::FunctionalConsolidation(Box::new(run))),
            ),
            Self::DimensionTrialBalance {
                selection,
                dimension,
                value,
            } => Ok(
                crate::dimension::trial_balance_at(db, book, selection, dimension, value, at)?
                    .map(|report| ReportOutput::DimensionTrialBalance(Box::new(report))),
            ),
            Self::RegulatorySchedule(selection) => {
                Ok(crate::statements::regulatory_at(db, book, selection, at)?
                    .map(|statement| ReportOutput::RegulatorySchedule(Box::new(statement))))
            }
            Self::CustomStatement(selection) => Ok(crate::custom_statement::report_at(
                db, cx, book, selection, at,
            )?
            .map(|report| ReportOutput::CustomStatement(Box::new(report)))),
        }
    }
}

/// Exact output recovered by replay; no successful report needs a HEAD lookup
/// for account display metadata, entry lineage or evidence commitments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReportOutput {
    TrialBalance(TrialBalance),
    FunctionalTrialBalance(Box<crate::functional_trial_balance::FunctionalTrialBalance>),
    ExplainBalance(Box<BalanceExplanation>),
    OpenItems(OpenItemsReport),
    Statement(Box<fa_statements::Statement>),
    FunctionalStatement(Box<fa_statements::Statement>),
    Consolidation(Box<crate::consolidation::Consolidation>),
    FunctionalConsolidation(Box<crate::consolidation::FunctionalConsolidation>),
    DimensionTrialBalance(Box<crate::dimension::DimensionTrialBalance>),
    /// The statement a regulatory schedule evaluates to.
    RegulatorySchedule(Box<fa_statements::Statement>),
    CustomStatement(Box<crate::custom_statement::CustomStatementReport>),
}

impl ReportOutput {
    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        match self {
            Self::TrialBalance(report) => report.known_at,
            Self::FunctionalTrialBalance(report) => report.known_at,
            Self::DimensionTrialBalance(report) => report.trial_balance.known_at,
            Self::ExplainBalance(report) => report.known_at,
            Self::OpenItems(report) => report.known_at,
            Self::Statement(report)
            | Self::FunctionalStatement(report)
            | Self::RegulatorySchedule(report) => CommitSeq(report.known_at),
            Self::Consolidation(report) => report.known_at,
            Self::FunctionalConsolidation(report) => report.group.known_at,
            Self::CustomStatement(report) => CommitSeq(report.statement.known_at),
        }
    }

    // Used only to compare today's literal result with an earlier report.
    // Recorded/visible/released history, account creation, period membership,
    // and fold watermarks remain part of the comparison.
    fn normalize_known_at(&mut self, known_at: CommitSeq) {
        match self {
            Self::TrialBalance(report) => report.known_at = known_at,
            Self::FunctionalTrialBalance(report) => report.known_at = known_at,
            Self::DimensionTrialBalance(report) => report.trial_balance.known_at = known_at,
            Self::ExplainBalance(report) => report.known_at = known_at,
            Self::OpenItems(report) => report.known_at = known_at,
            Self::Statement(report)
            | Self::FunctionalStatement(report)
            | Self::RegulatorySchedule(report) => {
                report.known_at = known_at.0;
            }
            Self::Consolidation(report) => report.set_known_at(known_at),
            Self::FunctionalConsolidation(report) => report.set_known_at(known_at),
            Self::CustomStatement(report) => report.set_known_at(known_at),
        }
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        match self {
            Self::TrialBalance(report) => report.canonical_bytes(),
            Self::FunctionalTrialBalance(report) => report.canonical_bytes(),
            Self::CustomStatement(report) => report.canonical_bytes(),
            Self::ExplainBalance(report) => report.canonical_bytes(),
            Self::OpenItems(report) => report.canonical_bytes(),
            Self::Statement(report) => report.canonical_bytes(),
            Self::FunctionalStatement(report) => {
                let mut w = Writer::new();
                w.fixed(FUNCTIONAL_STATEMENT_OUTPUT_FORMAT.as_bytes())
                    .str("retained-base-amounts")
                    .bytes(&report.canonical_bytes()?);
                w.finish()
            }
            Self::Consolidation(report) => report.canonical_bytes(),
            Self::FunctionalConsolidation(report) => report.canonical_bytes(),
            Self::DimensionTrialBalance(report) => report.canonical_bytes(),
            // Domain-separated, so a schedule's bytes never read as a
            // native statement's.
            Self::RegulatorySchedule(report) => {
                let mut w = Writer::new();
                w.fixed(REGULATORY_SCHEDULE_OUTPUT_FORMAT.as_bytes())
                    .bytes(&report.canonical_bytes()?);
                w.finish()
            }
        }
    }
}

/// A versioned content-addressed certificate. Its digest covers all fields
/// except itself; decoding and replay both verify that commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportCertificate {
    pub book_id: Id128,
    pub branch_id: Id128,
    pub known_at: CommitSeq,
    /// Present only for a read selected by an instant. Sequence-selected v1
    /// certificates retain their original bytes and digest domain.
    pub time_selection: Option<fa_journal::InstantSelection>,
    pub selection: ReportSelection,
    pub registry_digest: [u8; 32],
    pub journal_root: [u8; 32],
    pub journal_leaves: u64,
    pub inputs: Vec<NativeResultCertificate>,
    pub output: Vec<u8>,
    pub output_digest: [u8; 32],
    pub digest: [u8; 32],
}

#[cfg(test)]
impl ReportCertificate {
    /// The same certificate sealed under another registry closure, as an
    /// executable with other registries would have produced it (fa-t8gk).
    pub(crate) fn resealed_under(&self, closure: [u8; 32]) -> Self {
        let mut certificate = self.clone();
        certificate.registry_digest = closure;
        certificate.digest = digest(
            certificate.format(),
            &certificate
                .body_bytes()
                .expect("a decoded certificate encodes"),
        );
        certificate
    }

    /// The v1 raw-text closure a certificate retained before fa-t8gk carries.
    pub(crate) fn legacy_registry_closure(&self) -> [u8; 32] {
        legacy_registry_digest(&self.selection)
    }

    /// The pre-narrowing 8/9-registry v2 canonical closure a certificate
    /// retained before fa-t8gk narrowed the bound registry set carries.
    pub(crate) fn legacy_v2_registry_closure(&self) -> [u8; 32] {
        legacy_v2_registry_digest(&self.selection).expect("embedded registries parse canonically")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedTrialBalance {
    pub report: TrialBalance,
    pub certificate: ReportCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedReport {
    pub report: ReportOutput,
    pub certificate: ReportCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateSupersedingCase {
    /// The immutable case ordinal in this book.
    pub ordinal: u32,
    pub kind: fa_journal::CaseKind,
    /// The attested Disclosure document's content address, once disclosed.
    pub disclosure_document: Option<fa_model::Oid>,
    /// Public entry digest of the journaled Disclose transition. This binds
    /// the disclosure event, not merely the document it cites.
    pub disclosure_digest: Option<[u8; 32]>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertificateStatus {
    Current {
        checked_at: CommitSeq,
    },
    SupersededBy {
        checked_at: CommitSeq,
        later_entries: Vec<VId>,
        /// Cases whose posted members (or exact reversals of those members)
        /// occur among these relevant entries, ordered by case ordinal.
        cases: Vec<CertificateSupersedingCase>,
    },
}

fn invalid(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        why,
        "plan §13.6 / FA-INV-11 (the certified closure and exact output must replay)",
        "recreate the certificate from the original book and selector; retain its certified history and registry versions",
    )
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    h.update(value);
    h.finalize().0
}

fn encoding(e: fa_model::EncodeError) -> BookError {
    fa_journal::KernelError::from(fa_model::EntryError::from(e)).into()
}

/// The registries every report fold reads, in commitment order (fa-t8gk).
/// Native-unit folds do not read post-time admissibility, limits or rounding
/// laws. Functional statements additionally bind the FX and rounding laws
/// used to verify their retained valuations. Symbol IDs are bound at genesis
/// (`Book.symbols_digest`, checked with additive-prefix compatibility in
/// `symbols_match_at`) and per query in `NativeResultCertificate`.
const REPORT_REGISTRIES: &[(&str, &str)] = &[
    (
        "account_types",
        include_str!("../../../registries/account_types.toml"),
    ),
    (
        "entry_classes",
        include_str!("../../../registries/entry_classes.toml"),
    ),
    ("units", include_str!("../../../registries/units.toml")),
    ("foundations", include_str!("../../../franken-stack.lock")),
];
/// The pre-narrowing 8-registry list retained certificates bound before
/// fa-t8gk narrowed `REPORT_REGISTRIES` to the registries each report reads.
const LEGACY_REPORT_REGISTRIES: &[(&str, &str)] = &[
    (
        "account_types",
        include_str!("../../../registries/account_types.toml"),
    ),
    (
        "admissibility",
        include_str!("../../../registries/admissibility.toml"),
    ),
    (
        "entry_classes",
        include_str!("../../../registries/entry_classes.toml"),
    ),
    ("limits", include_str!("../../../registries/limits.toml")),
    (
        "rounding_laws",
        include_str!("../../../registries/rounding_laws.toml"),
    ),
    ("symbols", include_str!("../../../registries/symbols.toml")),
    ("units", include_str!("../../../registries/units.toml")),
    ("foundations", include_str!("../../../franken-stack.lock")),
];
/// Balance-explanation rendering resolves committed supersession reason codes
/// through `reason_codes.toml`; trial balances, open items, and statements do not.
const REASON_CODES: (&str, &str) = (
    "reason_codes",
    include_str!("../../../registries/reason_codes.toml"),
);

fn report_registries(selection: &ReportSelection) -> Vec<(&'static str, &'static str)> {
    let mut sources = REPORT_REGISTRIES.to_vec();
    if let ReportSelection::CustomStatement(selected) = selection {
        if selected.functional {
            sources.push(("fx_laws", include_str!("../../../registries/fx_laws.toml")));
        }
        sources.push((
            "rounding_laws",
            include_str!("../../../registries/rounding_laws.toml"),
        ));
    }
    if matches!(selection, ReportSelection::ExplainBalance { .. }) {
        sources.push(REASON_CODES);
    }
    if matches!(
        selection,
        ReportSelection::FunctionalStatement(_) | ReportSelection::FunctionalTrialBalance(_)
    ) {
        sources.extend([
            ("fx_laws", include_str!("../../../registries/fx_laws.toml")),
            (
                "rounding_laws",
                include_str!("../../../registries/rounding_laws.toml"),
            ),
        ]);
    }
    // Account roles select the run's accounts, and the NCI rounds under a
    // registered law.
    if matches!(
        selection,
        ReportSelection::Consolidation { .. } | ReportSelection::FunctionalConsolidation { .. }
    ) {
        sources.push((
            "account_roles",
            include_str!("../../../registries/account_roles.toml"),
        ));
        if selection.uses_functional_valuations() {
            sources.push(("fx_laws", include_str!("../../../registries/fx_laws.toml")));
        }
        sources.push((
            "rounding_laws",
            include_str!("../../../registries/rounding_laws.toml"),
        ));
    }
    sources
}

fn legacy_report_registries(selection: &ReportSelection) -> Vec<(&'static str, &'static str)> {
    let mut sources = LEGACY_REPORT_REGISTRIES.to_vec();
    if !matches!(selection, ReportSelection::TrialBalance(_)) {
        sources.push(REASON_CODES);
    }
    sources
}

/// The digest of one registry's parsed canonical content (bead fa-t8gk):
/// comments and layout never reach it, and every key and value does.
pub(crate) fn canonical_registry_digest(name: &str, text: &str) -> Result<[u8; 32], Refusal> {
    let document = fa_registry::toml::parse(text)
        .map_err(|e| invalid(format!("embedded registry {name} does not parse: {e}")))?;
    Ok(digest(
        b"fa:registry-canonical-digest:v1",
        &document.canonical_bytes(),
    ))
}

/// Registry identities are explicit inputs, not inferred from the executable's
/// version. A changed law or native engine pin requires the original environment
/// to replay this version; it cannot silently substitute new semantics. The v2
/// closure commits to each read registry's canonical content, so a comment or
/// layout edit, or an edit to a registry the report does not read, leaves the
/// certificate and its replay unchanged (bead fa-t8gk).
fn registry_digest(selection: &ReportSelection) -> Result<[u8; 32], Refusal> {
    canonical_closure(
        b"fa:report-registry-closure:v2",
        &report_registries(selection),
    )
}

/// The registry-bearing native profiles, including a summary trial balance's
/// stock/activity source and the closing-stock source inside a roll-forward.
/// Outer-certificate routing determines which composed reports require these
/// registries; bare trial-balance bundle routing remains unchanged.
fn offline_registry_profile(certificate: &ReportCertificate) -> bool {
    matches!(
        &certificate.selection,
        ReportSelection::Statement(_)
            | ReportSelection::OpenItems { .. }
            | ReportSelection::ExplainBalance { .. }
    ) || (certificate.branch_id == Id128::TRUNK
        && certificate.time_selection.is_none()
        && matches!(
            &certificate.selection,
            ReportSelection::TrialBalance(_)
                | ReportSelection::FunctionalTrialBalance(_)
                | ReportSelection::FunctionalStatement(_)
                | ReportSelection::Consolidation { .. }
                | ReportSelection::FunctionalConsolidation { .. }
        ))
}

/// Canonical registry inputs carried by native statements, open items,
/// explanations and sequence-selected native trial-balance sources for
/// summaries and roll-forwards.
/// The closure must be the one this certificate actually names. A historical
/// or custom book unit table cannot be replaced by the executable's defaults:
/// native statements render zero-valued lines for every book unit as well.
pub(crate) fn offline_report_registries(
    certificate: &ReportCertificate,
    units: &fa_money::UnitRegistry,
) -> Result<Vec<(String, Vec<u8>)>, Refusal> {
    if !offline_registry_profile(certificate) {
        return Err(invalid(
            "portable report registries require a native statement, open-item, balance-explanation, sequence-selected native or functional trial-balance, functional statement or one-book consolidation certificate",
        ));
    }
    let sources = report_registries(&certificate.selection);
    let current = registry_digest(&certificate.selection)?;
    if certificate.registry_digest != current {
        return Err(registry_unavailable(
            "offline report certificate",
            &certificate.registry_digest,
            &current,
            &sources,
        ));
    }
    let declared = fa_money::UnitRegistry::embedded()
        .map_err(|error| invalid(format!("embedded unit registry cannot be loaded: {error}")))?;
    if !units.iter().eq(declared.iter()) {
        return Err(Refusal::new(
            fa_notary::code::SCOPE_UNSUPPORTED,
            exit::REFUSAL,
            "the book's exact unit definitions differ from the certificate's portable registry closure",
            "plan §13.6 / FA-INV-11 (every report input, including unit meanings, is bound)",
            "export this report from a book whose immutable unit table matches its retained registry epoch; do not substitute or renumber historical units",
        ));
    }
    sources
        .into_iter()
        .map(|(name, text)| {
            let document = fa_registry::toml::parse(text).map_err(|error| {
                invalid(format!("embedded registry {name} does not parse: {error}"))
            })?;
            Ok((name.to_string(), document.canonical_bytes()))
        })
        .collect()
}

/// Export the original archived closure after a compatible executable upgrade.
/// The same interpreter checks used by replay apply before any registry bytes
/// leave the book; a current registry is never substituted for a saved epoch.
pub(crate) fn offline_report_registries_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<Vec<(String, Vec<u8>)>> {
    if !offline_registry_profile(certificate) {
        return Ok(Err(invalid(
            "portable report registries require a native statement, open-item, balance-explanation, sequence-selected native or functional trial-balance, functional statement or one-book consolidation certificate",
        )));
    }
    match registry_epoch::resolve(db, cx, book, certificate)? {
        Ok(Some(epoch)) => Ok(epoch.offline_documents(&book.units)),
        Ok(None)
            if matches!(
                &certificate.selection,
                ReportSelection::ExplainBalance { .. }
            ) =>
        {
            Ok(Err(Refusal::new(
                code::CERTIFICATE_REGISTRY_UNAVAILABLE,
                exit::ENVIRONMENT,
                "portable balance explanations require their original retained reason-code registry epoch",
                "plan §13.6 (every displayed reason is bound to its original source registry)",
                "retain the certificate with its original registry sources before exporting it; never substitute a newer reason-code registry",
            )))
        }
        Ok(None) => Ok(offline_report_registries(certificate, &book.units)),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// A displayed supersession code must resolve in the same immutable reason
/// source that travels with the explanation. Native replay proves the literal
/// code, but older committed histories may contain codes outside this profile.
pub(crate) fn check_explanation_reasons_at<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
    explanation: &BalanceExplanation,
) -> Outcome<()> {
    match registry_epoch::resolve(db, cx, book, certificate)? {
        Ok(Some(epoch)) => Ok(epoch.check_explanation_reasons(explanation)),
        Ok(None) => Ok(Err(Refusal::new(
            code::CERTIFICATE_REGISTRY_UNAVAILABLE,
            exit::ENVIRONMENT,
            "the explanation's original reason-code source is not retained",
            "plan §13.6 (each displayed reason requires its authenticated original meaning)",
            "retain the certificate with its original five-source registry epoch before export",
        ))),
        Err(refusal) => Ok(Err(refusal)),
    }
}

/// The v5 registry closure before the additive retained-carrying close law.
/// Every original law and every other registry remains bound byte-for-byte
/// canonically. This is usable only for prefixes whose valuations use those
/// original laws; it cannot authorize an entry under the omitted law.
fn pre_carrying_registry_digest(selection: &ReportSelection) -> Result<[u8; 32], Refusal> {
    let leaves = report_registries(selection)
        .into_iter()
        .map(|(name, text)| {
            if name != "fx_laws" {
                return Ok((name, canonical_registry_digest(name, text)?));
            }
            let mut document = fa_registry::toml::parse(text)
                .map_err(|e| invalid(format!("embedded registry {name} does not parse: {e}")))?;
            let laws = document
                .arrays
                .get_mut("law")
                .ok_or_else(|| invalid("embedded FX registry has no law rows"))?;
            let index = laws
                .iter()
                .position(|row| {
                    row.get("id").and_then(fa_registry::toml::Value::as_int) == Some(8)
                        && row
                            .get("version")
                            .and_then(fa_registry::toml::Value::as_int)
                            == Some(1)
                        && row.get("code").and_then(fa_registry::toml::Value::as_str)
                            == Some("year_end_close_carrying")
                })
                .ok_or_else(|| {
                    invalid("embedded FX registry has no retained-carrying close law")
                })?;
            laws.remove(index);
            Ok((
                name,
                digest(
                    b"fa:registry-canonical-digest:v1",
                    &document.canonical_bytes(),
                ),
            ))
        })
        .collect::<Result<Vec<_>, Refusal>>()?;
    Ok(registry_closure(b"fa:report-registry-closure:v2", &leaves))
}

fn pre_carrying_registry_covers(proposal: &fa_model::EntryPayload) -> bool {
    proposal.base_totals.as_ref().is_none_or(|totals| {
        fa_journal::fx::FxLawId::from_oid(&totals.fx_law_oid)
            .is_some_and(|law| (1..=7).contains(&law.id()))
    })
}

/// The pre-narrowing 8/9-registry v2 closure, kept so certificates retained
/// before fa-t8gk narrowed the bound registry set still replay while those
/// registries' canonical content is unchanged.
fn legacy_v2_registry_digest(selection: &ReportSelection) -> Result<[u8; 32], Refusal> {
    canonical_closure(
        b"fa:report-registry-closure:v2",
        &legacy_report_registries(selection),
    )
}

/// The v1 closure over raw file text, comments included. New certificates
/// never carry it; it is kept only so certificates retained before fa-t8gk
/// still replay while their registry text is unchanged.
fn legacy_registry_digest(selection: &ReportSelection) -> [u8; 32] {
    let leaves: Vec<(&str, [u8; 32])> = legacy_report_registries(selection)
        .into_iter()
        .map(|(name, text)| (name, digest(b"fa:report-registry:v1", text.as_bytes())))
        .collect();
    registry_closure(b"fa:report-registry-closure:v1", &leaves)
}

/// The closure over each named registry's canonical digest.
pub(crate) fn canonical_closure(
    domain: &[u8],
    sources: &[(&str, &str)],
) -> Result<[u8; 32], Refusal> {
    let leaves = sources
        .iter()
        .map(|(name, text)| Ok((*name, canonical_registry_digest(name, text)?)))
        .collect::<Result<Vec<_>, Refusal>>()?;
    Ok(registry_closure(domain, &leaves))
}

fn registry_closure(domain: &[u8], leaves: &[(&str, [u8; 32])]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for (name, leaf) in leaves {
        h.update(name.as_bytes());
        h.update(&[0]);
        h.update(leaf);
    }
    h.finalize().0
}

/// A certificate whose registry closure this executable does not carry: the
/// certificate may be sound, but replaying it needs its own registries.
pub(crate) fn registry_unavailable(
    what: &str,
    recorded: &[u8; 32],
    current: &[u8; 32],
    registries: &[(&str, &str)],
) -> Refusal {
    let names: Vec<&str> = registries.iter().map(|(name, _)| *name).collect();
    Refusal::new(
        code::CERTIFICATE_REGISTRY_UNAVAILABLE,
        exit::ENVIRONMENT,
        format!(
            "the {what} binds registry closure {} but this executable's closure over {} is {}; a registry's content differs",
            hex(recorded),
            names.join(", "),
            hex(current),
        ),
        "plan §13.6 / FA-INV-11 (a certificate binds the canonical content of the registries it was computed under)",
        "replay with the fa executable whose registries produced the certificate, or recreate the certificate under this executable's registries",
    )
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn statements(at: CommitSeq, selection: &ReportSelection) -> Vec<String> {
    let mut statements: Vec<_> = INPUTS
        .iter()
        .map(|(kind, fields)| {
            let projections: String = fields
                .split(',')
                .map(|field| format!(",n.{field}"))
                .collect();
            format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {} RETURN n{projections} ORDER BY n",
                at.0
            )
        })
        .collect();
    if selection.uses_functional_valuations() {
        // Restrict the payload closure to Rate documents. Unrelated documents
        // can require additional disclosure authority (for example bank data).
        // Every cited OID and the Rate mirror are independently bound below.
        statements.push(format!(
            "MATCH (n:Document) FOR SYSTEM_TIME AS OF SEQ {} WHERE n.code = 'Rate' RETURN n,n._fa_payload,n._fa_digest,n.book_id,n.code ORDER BY n",
            at.0
        ));
    }
    if let Some(kind) = selection.bound_dimension() {
        // Only the selected dimension's values: their declared parents decide
        // which tagged legs the report folds. Party and legal-entity values
        // carry other dimension ids and stay out of the closure.
        statements.push(format!(
            "MATCH (n:DimensionValue) FOR SYSTEM_TIME AS OF SEQ {} WHERE n.dimension_id = {} RETURN n,n._fa_payload,n.dimension_id ORDER BY n",
            at.0, kind.id
        ));
    }
    if let ReportSelection::CustomStatement(selected) = selection {
        statements.push(format!(
            "MATCH (n:StatementDefinition) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload,n._fa_digest,n.book_id ORDER BY n",
            at.0
        ));
        statements.push(format!(
            "MATCH (n:Approval) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n._fa_payload ORDER BY n",
            selected.activated_at.0
        ));
        statements.push(format!(
            "MATCH (n:Book) FOR SYSTEM_TIME AS OF SEQ {} RETURN n,n.security_policy_epoch ORDER BY n",
            selected.activated_at.0
        ));
        let before = selected.activated_at.0.saturating_sub(1);
        statements.push(format!(
            "MATCH (n:Account) FOR SYSTEM_TIME AS OF SEQ {before} RETURN n,n.code,n.name,n.account_type,n.normal_balance,n.posting,n.unit_policy,n.lower_bound,n.upper_bound,n.limit_scope,n._fa_payload,n.book_id ORDER BY n"
        ));
        statements.push(format!(
            "MATCH (n:Book) FOR SYSTEM_TIME AS OF SEQ {before} RETURN n,n._fa_payload,n.book_id ORDER BY n"
        ));
    }
    statements
}

fn input_snapshot(at: CommitSeq, selection: &ReportSelection, index: usize) -> CommitSeq {
    if let ReportSelection::CustomStatement(selected) = selection {
        let custom_offset = INPUTS.len()
            + usize::from(selection.uses_functional_valuations())
            + usize::from(selection.bound_dimension().is_some());
        if index == custom_offset + 1 || index == custom_offset + 2 {
            return selected.activated_at;
        }
        if index == custom_offset + 3 || index == custom_offset + 4 {
            return CommitSeq(selected.activated_at.0.saturating_sub(1));
        }
    }
    at
}

fn policy() -> GqlQueryPolicy {
    // Bounded native execution: exceeding the closure budget is a typed source
    // refusal, never a truncated certificate or an ungoverned eager fallback.
    GqlQueryPolicy::new(10_000_000, 1_000_000, 256 * 1024 * 1024, 256 * 1024 * 1024)
}

fn write_observation(w: &mut Writer, tick: &fa_time::TimeObservation) {
    w.u64(tick.recorded_at)
        .u64(tick.observed_utc_ns)
        .u8(tick.source)
        .bool(tick.monotonic_ok);
}

fn read_observation(r: &mut Reader<'_>) -> Result<fa_time::TimeObservation, fa_model::DecodeError> {
    Ok(fa_time::TimeObservation {
        recorded_at: r.u64("tick sequence")?,
        observed_utc_ns: r.u64("tick observed UTC nanoseconds")?,
        source: r.u8("tick source")?,
        monotonic_ok: r.bool("tick monotonic corroboration")?,
    })
}

fn write_time_selection(w: &mut Writer, time: &fa_journal::InstantSelection) {
    let resolution = &time.resolution;
    w.u64(resolution.requested_utc_ns)
        .u64(resolution.frontier)
        .u64(resolution.resolved_seq);
    write_observation(w, &resolution.lower);
    w.opt(resolution.upper.as_ref(), write_observation)
        .u128(time.lower_entry.0)
        .opt(time.upper_entry.as_ref(), |w, vid| {
            w.u128(vid.0);
        });
}

fn read_time_selection(
    r: &mut Reader<'_>,
) -> Result<fa_journal::InstantSelection, fa_model::DecodeError> {
    let requested_utc_ns = r.u64("requested UTC nanoseconds")?;
    let frontier = r.u64("TimeEvidence frontier")?;
    let resolved_seq = r.u64("resolved known-at")?;
    let lower = read_observation(r)?;
    let upper = r.opt("upper tick", read_observation)?;
    let lower_entry = VId(r.u128("lower tick entry")?);
    let upper_entry = r.opt("upper tick entry", |r| Ok(VId(r.u128("upper tick entry")?)))?;
    Ok(fa_journal::InstantSelection {
        resolution: fa_time::InstantResolution {
            requested_utc_ns,
            frontier,
            resolved_seq,
            lower,
            upper,
        },
        lower_entry,
        upper_entry,
    })
}

impl ReportCertificate {
    fn format(&self) -> &'static [u8] {
        match &self.selection {
            ReportSelection::TrialBalance(_) if self.time_selection.is_some() => {
                INSTANT_CERTIFICATE_FORMAT
            }
            ReportSelection::TrialBalance(_) => CERTIFICATE_FORMAT,
            ReportSelection::FunctionalTrialBalance(_) => {
                FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT
            }
            ReportSelection::Statement(_) => STATEMENT_CERTIFICATE_FORMAT,
            ReportSelection::FunctionalStatement(_) => FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT,
            ReportSelection::Consolidation { .. } => CONSOLIDATION_CERTIFICATE_FORMAT,
            ReportSelection::FunctionalConsolidation { .. } => {
                FUNCTIONAL_CONSOLIDATION_CERTIFICATE_FORMAT
            }
            ReportSelection::DimensionTrialBalance { .. } => {
                DIMENSION_TRIAL_BALANCE_CERTIFICATE_FORMAT
            }
            ReportSelection::RegulatorySchedule(_) => REGULATORY_SCHEDULE_CERTIFICATE_FORMAT,
            ReportSelection::CustomStatement(selected) if selected.functional => {
                FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT
            }
            ReportSelection::CustomStatement(_) => CUSTOM_STATEMENT_CERTIFICATE_FORMAT,
            _ => REPORT_CERTIFICATE_FORMAT,
        }
    }

    #[must_use]
    pub const fn output_format(&self) -> &'static str {
        self.selection.output_format()
    }

    fn body_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut w = Writer::new();
        w.fixed(self.format())
            .str(REPLAY_SCOPE)
            .str(AUTHORITY)
            .str(self.output_format())
            .fixed(&self.book_id.0)
            .fixed(&self.branch_id.0)
            .u64(self.known_at.0);
        self.selection.write(&mut w)?;
        w.fixed(&self.registry_digest)
            .fixed(&self.journal_root)
            .u64(self.journal_leaves)
            .list(&self.inputs, |w, input| {
                w.bytes(&input.canonical_bytes());
            })
            .bytes(&self.output)
            .fixed(&self.output_digest);
        if self.format() == REPORT_CERTIFICATE_FORMAT
            || self.format() == STATEMENT_CERTIFICATE_FORMAT
            || self.format() == FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT
            || self.format() == CONSOLIDATION_CERTIFICATE_FORMAT
            || self.format() == FUNCTIONAL_CONSOLIDATION_CERTIFICATE_FORMAT
            || self.format() == DIMENSION_TRIAL_BALANCE_CERTIFICATE_FORMAT
            || self.format() == REGULATORY_SCHEDULE_CERTIFICATE_FORMAT
            || self.format() == FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT
            || self.format() == CUSTOM_STATEMENT_CERTIFICATE_FORMAT
            || self.format() == FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT
        {
            w.opt(self.time_selection.as_ref(), write_time_selection);
        } else if let Some(time) = &self.time_selection {
            write_time_selection(&mut w, time);
        }
        w.finish()
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, fa_model::EncodeError> {
        let mut body = self.body_bytes()?;
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(invalid(
                "report certificate exceeds the 64 MiB format limit",
            ));
        }
        let decode = || -> Result<Self, fa_model::DecodeError> {
            let mut r = Reader::new(bytes);
            // V10 is the first two-digit version. Preserve every earlier wire
            // header and consume its exact length before reading framed fields.
            let version = if bytes.starts_with(FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT) {
                r.fixed::<{ FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT.len() }>(
                    "certificate format",
                )?;
                12
            } else if bytes.starts_with(CUSTOM_STATEMENT_CERTIFICATE_FORMAT) {
                r.fixed::<{ CUSTOM_STATEMENT_CERTIFICATE_FORMAT.len() }>("certificate format")?;
                11
            } else if bytes.starts_with(FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT) {
                r.fixed::<{ FUNCTIONAL_TRIAL_BALANCE_CERTIFICATE_FORMAT.len() }>(
                    "certificate format",
                )?;
                10
            } else {
                let format = r.fixed::<{ CERTIFICATE_FORMAT.len() }>("certificate format")?;
                if format == CERTIFICATE_FORMAT {
                    1
                } else if format == INSTANT_CERTIFICATE_FORMAT {
                    2
                } else if format == REPORT_CERTIFICATE_FORMAT {
                    3
                } else if format == STATEMENT_CERTIFICATE_FORMAT {
                    4
                } else if format == FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT {
                    5
                } else if format == CONSOLIDATION_CERTIFICATE_FORMAT {
                    6
                } else if format == FUNCTIONAL_CONSOLIDATION_CERTIFICATE_FORMAT {
                    7
                } else if format == DIMENSION_TRIAL_BALANCE_CERTIFICATE_FORMAT {
                    8
                } else if format == REGULATORY_SCHEDULE_CERTIFICATE_FORMAT {
                    9
                } else {
                    return Err(r.invalid("report certificate format"));
                }
            };
            for (name, expected) in [("replay scope", REPLAY_SCOPE), ("authority", AUTHORITY)] {
                if r.str(64, name)? != expected {
                    return Err(r.invalid(name));
                }
            }
            let output_format = r.str(64, "output format")?;
            let book_id = Id128(r.fixed("book id")?);
            let branch_id = Id128(r.fixed("branch id")?);
            let known_at = CommitSeq(r.u64("known-at")?);
            let selection = ReportSelection::read(&mut r, version)?;
            if output_format != selection.output_format() {
                return Err(r.invalid("selected report output format"));
            }
            let registry_digest = r.fixed("registry closure")?;
            let journal_root = r.fixed("journal root")?;
            let journal_leaves = r.u64("journal leaves")?;
            let required_inputs = INPUTS.len()
                + usize::from(selection.uses_functional_valuations())
                + usize::from(selection.bound_dimension().is_some())
                + CUSTOM_STATEMENT_INPUTS
                    * usize::from(matches!(selection, ReportSelection::CustomStatement(_)));
            let count = r.count(required_inputs, "native inputs")?;
            if count != required_inputs {
                return Err(r.invalid("complete native input closure"));
            }
            let mut inputs = Vec::new();
            for _ in 0..count {
                let input = r.bytes(MAX_NATIVE_BYTES, "native certificate")?;
                inputs.push(
                    NativeResultCertificate::decode(input)
                        .map_err(|_| r.invalid("native certificate"))?,
                );
            }
            let output = r.bytes(MAX_CERTIFICATE_BYTES, "report output")?.to_vec();
            let output_digest = r.fixed("output digest")?;
            let time_selection = match version {
                1 => None,
                2 => Some(read_time_selection(&mut r)?),
                _ => r.opt("TimeEvidence selection", read_time_selection)?,
            };
            let digest = r.fixed("certificate digest")?;
            r.finish()?;
            Ok(Self {
                book_id,
                branch_id,
                known_at,
                time_selection,
                selection,
                registry_digest,
                journal_root,
                journal_leaves,
                inputs,
                output,
                output_digest,
                digest,
            })
        };
        let certificate =
            decode().map_err(|e| invalid(format!("malformed report certificate: {e}")))?;
        certificate.validate()?;
        Ok(certificate)
    }

    fn validate(&self) -> Result<(), Refusal> {
        if self.branch_id != Id128::TRUNK || !self.selection.is_canonical() {
            return Err(invalid(
                "unsupported branch or noncanonical report selector",
            ));
        }
        if let ReportSelection::CustomStatement(selected) = &self.selection
            && selected.activated_at > self.known_at
        {
            return Err(invalid(
                "statement activation is later than the report's known-at",
            ));
        }
        if let Some(time) = &self.time_selection
            && (!time.is_canonical() || time.resolution.resolved_seq != self.known_at.0)
        {
            return Err(invalid(
                "TimeEvidence brackets do not resolve to the certified sequence",
            ));
        }
        let expected = statements(self.known_at, &self.selection);
        if self.inputs.len() != expected.len()
            || self
                .inputs
                .iter()
                .zip(expected)
                .enumerate()
                .any(|(index, (input, statement))| {
                    input.statement != statement
                        || input.plan.snapshot_seq
                            != input_snapshot(self.known_at, &self.selection, index)
                })
        {
            return Err(invalid(
                "native input closure differs from the report's fixed historical selectors",
            ));
        }
        let mut identities = BTreeMap::new();
        for input in &self.inputs {
            if input.database_identity != self.inputs[0].database_identity
                || identities
                    .insert(input.plan.snapshot_seq, input.snapshot_identity)
                    .is_some_and(|identity| identity != input.snapshot_identity)
            {
                return Err(invalid(
                    "native inputs name different books or disagree on a selected snapshot identity",
                ));
            }
        }
        if digest(b"fa:report-output:v1", &self.output) != self.output_digest {
            return Err(invalid(
                "the certified output bytes do not match their digest",
            ));
        }
        let body = self.body_bytes().map_err(|e| invalid(e.to_string()))?;
        if body.len().saturating_add(32) > MAX_CERTIFICATE_BYTES
            || digest(self.format(), &body) != self.digest
        {
            return Err(invalid(
                "the report certificate's content digest does not match",
            ));
        }
        Ok(())
    }
}

pub(crate) fn certify<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    selection: TrialBalanceSelection,
    known_at: Option<CommitSeq>,
) -> Outcome<CertifiedTrialBalance> {
    Ok(certify_report(db, cx, book, selection.into(), known_at)?.and_then(certified_trial_balance))
}

pub(crate) fn certify_instant<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    selection: TrialBalanceSelection,
    requested_utc_ns: u64,
) -> Outcome<CertifiedTrialBalance> {
    Ok(
        certify_report_instant(db, cx, book, selection.into(), requested_utc_ns)?
            .and_then(certified_trial_balance),
    )
}

fn certified_trial_balance(report: CertifiedReport) -> Result<CertifiedTrialBalance, Refusal> {
    let CertifiedReport {
        report,
        certificate,
    } = report;
    match report {
        ReportOutput::TrialBalance(report) => Ok(CertifiedTrialBalance {
            report,
            certificate,
        }),
        _ => Err(invalid("the selected report is not a trial balance")),
    }
}

pub(crate) fn certify_report<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    selection: ReportSelection,
    known_at: Option<CommitSeq>,
) -> Outcome<CertifiedReport> {
    certify_selected(db, cx, book, selection, known_at, None)
}

pub(crate) fn certify_report_instant<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    selection: ReportSelection,
    requested_utc_ns: u64,
) -> Outcome<CertifiedReport> {
    let time = match fa_journal::resolve_instant_at(db, &cx.query(), book, requested_utc_ns, None)?
    {
        Ok(time) => time,
        Err(refusal) => return Ok(Err(refusal)),
    };
    certify_selected(
        db,
        cx,
        book,
        selection,
        Some(CommitSeq(time.resolution.resolved_seq)),
        Some(time),
    )
}

pub(crate) fn context_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    at: CommitSeq,
) -> Result<(), BookError> {
    let row = db
        .vertex_at(book_root(), at)
        .map_err(fa_journal::KernelError::from)?
        .filter(|row| row.labels.contains(&label::BOOK))
        .ok_or_else(|| {
            fa_registers::RegisterError::InvalidSelection(format!(
                "the book does not exist at sequence {}",
                at.0
            ))
        })?;
    let spec = BookSpec::decode(&bytes(
        &row,
        property::FA_PAYLOAD,
        "certified book payload",
    )?)?;
    if spec.book_id != book.book_id
        || spec.calendar != book.calendar
        || bytes(&row, property::BOOK_ID, "certified book id")? != book.book_id.0
        || !symbols_match_at(db, book, &row, at)?
        || bytes(
            &row,
            property::UNIT_TABLE_DIGEST,
            "certified unit table digest",
        )? != fa_model::unit::unit_table_digest(&book.units).map_err(encoding)?
    {
        return Err(fa_journal::KernelError::Corrupt(
            "report context differs from the book and calendar at its selected sequence".into(),
        )
        .into());
    }
    for (id, unit) in book.units.iter() {
        let vid = fa_model::unit_vid(book.book_id, &format!("{}@v{}", unit.code, unit.version));
        let row = db
            .vertex_at(vid, at)
            .map_err(fa_journal::KernelError::from)?
            .filter(|row| row.labels.contains(&label::UNIT))
            .ok_or_else(|| {
                fa_journal::KernelError::Corrupt(format!(
                    "registered unit {} is absent at sequence {}",
                    unit.code, at.0
                ))
            })?;
        let definition = fa_model::UnitDefinition {
            id,
            unit: unit.clone(),
        }
        .canonical_bytes()
        .map_err(encoding)?;
        if bytes(&row, property::FA_PAYLOAD, "certified unit definition")? != definition
            || int(&row, property::UNIT_ID, "certified unit id")? != i64::from(id.0)
            || text(&row, property::CODE, "certified unit code")? != unit.code
            || int(&row, property::SCALE, "certified unit scale")? != i64::from(unit.scale)
            || int(&row, property::VERSION, "certified unit version")? != i64::from(unit.version)
        {
            return Err(fa_journal::KernelError::Corrupt(format!(
                "registered unit {} differs from its certified historical definition",
                unit.code
            ))
            .into());
        }
    }
    Ok(())
}

/// Additive label IDs do not reinterpret a prior binding. The retained
/// digest must nevertheless be the Book's original native creation value:
/// changing a newer book's mirror to a valid older prefix is corruption.
/// Mutable clock, security-policy and accumulator mirrors are deliberately
/// outside this immutable genesis projection.
fn symbols_match_at<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    selected: &fgdb::VertexRow,
    at: CommitSeq,
) -> Result<bool, BookError> {
    let retained = bytes(
        selected,
        property::SYMBOLS_DIGEST,
        "certified symbol digest",
    )?;
    let Ok(retained) = <[u8; 32]>::try_from(retained) else {
        return Ok(false);
    };
    if retained == book.symbols.digest().0 {
        return Ok(true);
    }
    if !book.symbols.matches_label_prefix_digest(Digest(retained)) {
        return Ok(false);
    }
    let Some(genesis) = fa_journal::scratch::source_genesis(db)? else {
        return Err(fa_journal::KernelError::Corrupt(
            "symbol compatibility requires the Book's retained native creation".into(),
        )
        .into());
    };
    if genesis > at || selected.retired_at.is_some_and(|retired| retired <= at) {
        return Ok(false);
    }
    let Some(before) = genesis.0.checked_sub(1) else {
        return Ok(false);
    };
    let mut history = db
        .delta_since(CommitSeq(before))
        .map_err(fa_journal::KernelError::from)?;
    let Some(batch) = history.next().filter(|batch| batch.commit_seq() == genesis) else {
        return Err(fa_journal::KernelError::Corrupt(
            "the Book's native creating commit is unavailable for symbol compatibility".into(),
        )
        .into());
    };
    let mut births = 0_u8;
    for coordinate in batch.coordinate_entries() {
        for delta in &coordinate.rows {
            let DeltaRow::CreateVertex {
                vid,
                birth_ordinal,
                labels,
                props,
                ..
            } = delta
            else {
                continue;
            };
            if *vid != book_root() {
                continue;
            }
            births = births.saturating_add(1);
            if *birth_ordinal != selected.birth_ordinal || labels != &selected.labels {
                return Ok(false);
            }
            for key in [
                property::FA_PAYLOAD,
                property::BOOK_ID,
                property::BASE_UNIT,
                property::CALENDAR_ID,
                property::SYMBOLS_DIGEST,
                property::UNIT_TABLE_DIGEST,
            ] {
                let original = props
                    .iter()
                    .find_map(|(candidate, value)| (*candidate == key).then_some(value));
                if original.is_none() || original != fa_journal::rows::prop(selected, key) {
                    return Ok(false);
                }
            }
        }
    }
    Ok(births == 1)
}

#[cfg(test)]
mod context_tests;

fn certify_selected<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    selection: ReportSelection,
    known_at: Option<CommitSeq>,
    time_selection: Option<fa_journal::InstantSelection>,
) -> Outcome<CertifiedReport> {
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    let selection = selection.normalize();
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    let at = known_at.unwrap_or(head);
    if at > head {
        if selection.statement_columns().is_some() {
            return Ok(Err(crate::statements::invalid(format!(
                "statement known-at {} is beyond book head {}",
                at.0, head.0
            ))));
        }
        return Err(fa_registers::RegisterError::InvalidSelection(format!(
            "known-at sequence {} is beyond book head {}",
            at.0, head.0
        ))
        .into());
    }
    if !selection.is_canonical() {
        if selection.statement_columns().is_some() {
            return Ok(Err(crate::statements::invalid(
                "select nonempty, bounded statement periods",
            )));
        }
        return Err(fa_registers::RegisterError::InvalidSelection(
            "select a nonempty, bounded report selector".into(),
        )
        .into());
    }
    // Empty as-of/open-item folds must not certify a coordinate before genesis,
    // or fold with a calendar/units context that the native closure never read.
    context_at(db, book, at)?;
    if selection.uses_functional_valuations()
        && let Err(refusal) = functional::verify_sources(db, cx, book, at)?
    {
        return Ok(Err(refusal));
    }
    let report = match selection.report(db, &query, book, at)? {
        Ok(report) => report,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if matches!(&report, ReportOutput::TrialBalance(report) if !report.is_balanced()) {
        return Ok(Err(invalid(
            "the journal trial balance is not balanced in every unit",
        )));
    }
    let mut inputs = Vec::new();
    for statement in statements(at, &selection) {
        query.checkpoint().map_err(BookError::Context)?;
        let (_, certificate) = db
            .execute_certified(
                &query,
                &statement,
                &GqlParameters::new(),
                book.symbols.clone(),
                policy(),
            )
            .map_err(BookError::CertifiedRead)?;
        inputs.push(certificate);
    }
    let journal = match Journal::read(db, book, Some(at), None)? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = unchanged_entries(db, &query, &journal)? {
        return Ok(Err(refusal));
    }
    let output = report.canonical_bytes().map_err(encoding)?;
    let mut certificate = ReportCertificate {
        book_id: book.book_id,
        branch_id: Id128::TRUNK,
        known_at: at,
        time_selection,
        registry_digest: match registry_digest(&selection) {
            Ok(closure) => closure,
            Err(refusal) => return Ok(Err(refusal)),
        },
        selection,
        journal_root: journal.root(),
        journal_leaves: journal.len(),
        inputs,
        output_digest: digest(b"fa:report-output:v1", &output),
        output,
        digest: [0; 32],
    };
    certificate.digest = digest(
        certificate.format(),
        &certificate.body_bytes().map_err(encoding)?,
    );
    if let Err(refusal) = certificate.validate() {
        return Ok(Err(refusal));
    }
    Ok(Ok(CertifiedReport {
        report,
        certificate,
    }))
}

/// A snapshot-only replay would overlook an in-place rewrite committed after
/// the certificate. The posting journal is immutable, so each certified entry
/// must still exist at HEAD with the same creating sequence and full bytes.
fn unchanged_entries<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    journal: &Journal,
) -> Outcome<()> {
    for leaf in &journal.leaves {
        cx.checkpoint().map_err(BookError::Context)?;
        let Some(row) = db.vertex(leaf.vid).map_err(fa_journal::KernelError::from)? else {
            return Ok(Err(invalid(format!(
                "certified journal entry {:032x} was retired",
                leaf.vid.0
            ))));
        };
        if !row.labels.contains(&label::ENTRY)
            || row.created_at != leaf.envelope.commit_seq
            || bytes(&row, property::FA_PAYLOAD, "certified entry payload")
                .ok()
                .as_deref()
                != Some(leaf.payload.as_slice())
            || bytes(&row, property::FA_DIGEST, "certified entry digest")
                .ok()
                .as_deref()
                != Some(leaf.envelope.record_digest.as_slice())
        {
            return Ok(Err(invalid(format!(
                "certified journal entry {:032x} was rewritten",
                leaf.vid.0
            ))));
        }
    }
    Ok(Ok(()))
}

pub(crate) fn replay<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<TrialBalance> {
    if !matches!(&certificate.selection, ReportSelection::TrialBalance(_)) {
        return Ok(Err(invalid(
            "the certificate's selected report is not a trial balance",
        )));
    }
    Ok(
        replay_report(db, cx, book, certificate)?.and_then(|report| match report {
            ReportOutput::TrialBalance(report) => Ok(report),
            _ => Err(invalid("the replayed report is not a trial balance")),
        }),
    )
}

pub(crate) fn replay_report<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<ReportOutput> {
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    if let Err(refusal) = certificate.validate() {
        return Ok(Err(refusal));
    }
    if certificate.book_id != book.book_id {
        return Ok(Err(invalid("the certificate belongs to a different book")));
    }
    let current = match registry_digest(&certificate.selection) {
        Ok(closure) => closure,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let archived_epoch = match registry_epoch::resolve(db, &query, book, certificate)? {
        Ok(epoch) => epoch,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let legacy_v2 = match legacy_v2_registry_digest(&certificate.selection) {
        Ok(closure) => closure,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let pre_carrying = if certificate.registry_digest != current
        && matches!(
            &certificate.selection,
            ReportSelection::FunctionalStatement(_)
        ) {
        match pre_carrying_registry_digest(&certificate.selection) {
            Ok(closure) => certificate.registry_digest == closure,
            Err(refusal) => return Ok(Err(refusal)),
        }
    } else {
        false
    };
    if certificate.registry_digest != current
        && archived_epoch.is_none()
        && !pre_carrying
        && (matches!(
            &certificate.selection,
            ReportSelection::FunctionalStatement(_)
                | ReportSelection::FunctionalTrialBalance(_)
                | ReportSelection::Consolidation { .. }
                | ReportSelection::FunctionalConsolidation { .. }
                | ReportSelection::DimensionTrialBalance { .. }
                | ReportSelection::RegulatorySchedule(_)
                | ReportSelection::CustomStatement(_)
        ) || (certificate.registry_digest != legacy_v2
            && certificate.registry_digest != legacy_registry_digest(&certificate.selection)))
    {
        return Ok(Err(registry_unavailable(
            "report certificate",
            &certificate.registry_digest,
            &current,
            &report_registries(&certificate.selection),
        )));
    }
    if let Some(expected) = &certificate.time_selection {
        // The later upper tick can lie after the report's sequence. Resolve
        // against the saved observed frontier, never today's HEAD, and verify
        // the retained tick payloads against their unchanged current records.
        let actual = match fa_journal::resolve_instant_at(
            db,
            &query,
            book,
            expected.resolution.requested_utc_ns,
            Some(CommitSeq(expected.resolution.frontier)),
        ) {
            Ok(Ok(actual)) => actual,
            Ok(Err(refusal)) => return Ok(Err(invalid(refusal.message))),
            Err(fa_journal::KernelError::Corrupt(why)) => {
                return Ok(Err(invalid(format!("TimeEvidence does not replay: {why}"))));
            }
            Err(error) => return Err(error.into()),
        };
        if &actual != expected {
            return Ok(Err(invalid(
                "TimeEvidence resolution differs from the certified frontier and brackets",
            )));
        }
    }
    for (index, input) in certificate.inputs.iter().enumerate() {
        if let Err(error) = db.replay(
            &query,
            input,
            &GqlParameters::new(),
            book.symbols.clone(),
            policy(),
        ) {
            let extra = if certificate.selection.bound_dimension().is_some() {
                "dimension values"
            } else {
                "Rate documents"
            };
            return Ok(Err(invalid(format!(
                "native input {index} ({}) does not replay: {error}",
                INPUTS.get(index).map_or(extra, |(kind, _)| *kind)
            ))));
        }
    }
    if let Err(error) = context_at(db, book, certificate.known_at) {
        return Ok(Err(invalid(format!(
            "the certified historical book context is unavailable: {error}"
        ))));
    }
    let journal = match Journal::read(db, book, Some(certificate.known_at), None)? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if journal.root() != certificate.journal_root || journal.len() != certificate.journal_leaves {
        return Ok(Err(invalid(
            "the accounting journal prefix does not match the certified one",
        )));
    }
    if let Err(refusal) = unchanged_entries(db, &query, &journal)? {
        return Ok(Err(refusal));
    }
    if pre_carrying {
        for leaf in &journal.leaves {
            let entry = Entry::decode(&leaf.payload).map_err(fa_journal::KernelError::from)?;
            if !pre_carrying_registry_covers(&entry.proposal) {
                return Ok(Err(registry_unavailable(
                    "functional report certificate whose prefix uses a law absent from its registry",
                    &certificate.registry_digest,
                    &current,
                    &report_registries(&certificate.selection),
                )));
            }
        }
    }
    if certificate.selection.uses_functional_valuations()
        && let Err(refusal) = functional::verify_sources(db, cx, book, certificate.known_at)?
    {
        return Ok(Err(refusal));
    }
    let report = match certificate
        .selection
        .report(db, &query, book, certificate.known_at)?
    {
        Ok(report) => report,
        Err(refusal) => {
            return Ok(Err(invalid(format!(
                "the selected report no longer evaluates: {}",
                refusal.message
            ))));
        }
    };
    let output = report.canonical_bytes().map_err(encoding)?;
    if output != certificate.output {
        let first = output
            .iter()
            .zip(&certificate.output)
            .position(|(a, b)| a != b)
            .unwrap_or(output.len().min(certificate.output.len()));
        return Ok(Err(invalid(format!(
            "{} differs from its certified output at canonical byte {first}",
            certificate.output_format()
        ))));
    }
    Ok(Ok(report))
}

pub(crate) fn status<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<CertificateStatus> {
    let query = cx.query();
    let report = match replay_report(db, cx, book, certificate)? {
        Ok(report) => report,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let head = db.frontier().map_err(fa_journal::KernelError::from)?;
    if let Err(error) = context_at(db, book, head) {
        return Ok(Err(invalid(format!(
            "the current book context no longer matches the certified context: {error}"
        ))));
    }
    let journal = match Journal::read(db, book, Some(head), None)? {
        Ok(journal) => journal,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let mut entries = BTreeMap::new();
    for leaf in &journal.leaves {
        entries.insert(
            leaf.vid,
            Entry::decode(&leaf.payload).map_err(fa_journal::KernelError::from)?,
        );
    }
    let (additional_report, chart_entries) = match statement_chart_additions(
        db,
        &query,
        book,
        certificate,
        &report,
        &journal,
        &entries,
    )? {
        Ok(additions) => additions,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // A value created under the reported one since joins what a rerun at
    // HEAD folds: its creation and later legs tagged with it are relevant.
    let dimension_report = match &report {
        ReportOutput::DimensionTrialBalance(tagged) => {
            let Some(kind) = fa_model::dimension_kind(&tagged.dimension) else {
                return Ok(Err(invalid("the certified dimension is not registered")));
            };
            let Some(values) = crate::dimension::values_under(db, &kind, &tagged.value, head)?
            else {
                return Ok(Err(invalid(format!(
                    "the certified {} value `{}` is absent at HEAD",
                    tagged.dimension, tagged.value
                ))));
            };
            let mut current = tagged.as_ref().clone();
            current.values = values.into_keys().collect();
            Some(ReportOutput::DimensionTrialBalance(Box::new(current)))
        }
        _ => None,
    };
    let relevance_report = additional_report
        .as_ref()
        .or(dimension_report.as_ref())
        .unwrap_or(&report);
    if let Err(refusal) = unchanged_account_metadata(db, &query, relevance_report, head)? {
        return Ok(Err(refusal));
    }
    let mut later_entries = Vec::new();
    let mut migration_visibility = BTreeMap::new();
    for leaf in &journal.leaves {
        query.checkpoint().map_err(BookError::Context)?;
        if leaf.envelope.commit_seq <= certificate.known_at {
            continue;
        }
        let entry = &entries[&leaf.vid];
        let mut relevant = chart_entries.contains(&leaf.vid)
            || (fa_journal::migration::visible_at(db, entry, head, &mut migration_visibility)?
                && selected(
                    book,
                    &certificate.selection,
                    relevance_report,
                    entry,
                    &entries,
                )?);
        if entry.proposal.class == EntryClass::RESOLUTION
            && let Some(target) = entry
                .proposal
                .pending
                .as_ref()
                .and_then(|p| p.resolution_of)
            && let Some(original) = entries.get(&target.vid)
        {
            relevant |= selected(
                book,
                &certificate.selection,
                relevance_report,
                original,
                &entries,
            )?;
        }
        if let Some(ControlPayload::MigrationControl { run_ref, kind, .. }) =
            &entry.proposal.control
            && *kind == fa_journal::migration::kind::FINALIZE
        {
            for migrated in entries.values() {
                if matches!(&migrated.proposal.origin, EntryOrigin::Migration { run_ref: origin, .. } if origin == run_ref)
                    && fa_journal::migration::visible_at(
                        db,
                        migrated,
                        head,
                        &mut migration_visibility,
                    )?
                {
                    relevant |= selected(
                        book,
                        &certificate.selection,
                        relevance_report,
                        migrated,
                        &entries,
                    )?;
                }
            }
        }
        if relevant {
            later_entries.push(leaf.vid);
        }
    }
    if later_entries.is_empty() {
        // Some report inputs can change without an accounting entry: period
        // creation changes an AsOf report's period list, and a corrupt mirror
        // can expose an old migration chunk. Never label an unexplained
        // change Current merely because the entry scan found no new cause.
        query.checkpoint().map_err(BookError::Context)?;
        let mut current = match certificate.selection.report(db, &query, book, head) {
            Ok(Ok(report)) => report,
            Ok(Err(refusal)) => {
                return Ok(Err(invalid(format!(
                    "current report no longer satisfies its definition: {}",
                    refusal.message
                ))));
            }
            Err(error) => {
                return Ok(Err(invalid(format!(
                    "current report changed outside later contributing entries: {error}"
                ))));
            }
        };
        current.normalize_known_at(report.known_at());
        let current_output = match current.canonical_bytes() {
            Ok(output) => output,
            Err(error) => {
                return Ok(Err(invalid(format!(
                    "current report changed outside later contributing entries: cannot encode its output: {error}"
                ))));
            }
        };
        if current_output != certificate.output {
            return Ok(Err(invalid(
                "current report changed outside later contributing entries; its period selection, metadata or historical contributions differ",
            )));
        }
        return Ok(Ok(CertificateStatus::Current { checked_at: head }));
    }
    let cases = case_status::superseding_cases(
        book.book_id,
        journal
            .leaves
            .iter()
            .map(|leaf| (leaf.vid, leaf.envelope.commit_seq, &entries[&leaf.vid])),
        &later_entries,
    )?;
    Ok(Ok(CertificateStatus::SupersededBy {
        checked_at: head,
        later_entries,
        cases,
    }))
}

/// Extend only the account-membership view used for later-entry relevance.
/// The historical output remains untouched for replay and exact comparison.
/// A chart install is relevant even when its new covered leaves have no legs:
/// the statement's mandatory partition records those zero accounts too.
fn statement_chart_additions<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
    report: &ReportOutput,
    journal: &Journal,
    entries: &BTreeMap<VId, Entry>,
) -> Outcome<(Option<ReportOutput>, BTreeSet<VId>)> {
    type Wrap = fn(Box<fa_statements::Statement>) -> ReportOutput;
    let (partition, statement, wrap): (
        StatementPartition<'_>,
        &fa_statements::Statement,
        Option<Wrap>,
    ) = match (&certificate.selection, report) {
        (ReportSelection::Statement(selection), ReportOutput::Statement(statement)) => (
            StatementPartition::ByType(&selection.definition),
            statement.as_ref(),
            Some(ReportOutput::Statement),
        ),
        (
            ReportSelection::FunctionalStatement(selection),
            ReportOutput::FunctionalStatement(statement),
        ) => (
            StatementPartition::ByType(&selection.definition),
            statement.as_ref(),
            Some(ReportOutput::FunctionalStatement),
        ),
        (
            ReportSelection::RegulatorySchedule(selection),
            ReportOutput::RegulatorySchedule(statement),
        ) => (
            StatementPartition::ByCode(&selection.schedule.statement_definition),
            statement.as_ref(),
            Some(ReportOutput::RegulatorySchedule),
        ),
        (ReportSelection::CustomStatement(selection), ReportOutput::CustomStatement(report)) => (
            StatementPartition::ByCode(&selection.definition),
            &report.statement,
            None,
        ),
        _ => return Ok(Ok((None, BTreeSet::new()))),
    };
    let mut additions = Vec::new();
    let mut chart_entries = BTreeSet::new();
    let mut mapped_ids: BTreeSet<_> = statement
        .mappings
        .iter()
        .map(|mapping| mapping.account.id)
        .collect();
    for leaf in &journal.leaves {
        if leaf.envelope.commit_seq <= certificate.known_at {
            continue;
        }
        cx.checkpoint().map_err(BookError::Context)?;
        let entry = &entries[&leaf.vid];
        if entry.proposal.class != EntryClass::SCHEMA_CONTROL
            || !matches!(&entry.proposal.origin, EntryOrigin::Control { control_kind, .. }
                if *control_kind == fa_model::ControlKind::CHART_INSTALL)
        {
            continue;
        }
        let canonical_bytes = match &entry.proposal.control {
            Some(ControlPayload::SchemaChange {
                kind: 1,
                canonical_bytes,
            }) => canonical_bytes,
            Some(ControlPayload::SchemaChange {
                kind: 2..=11 | fa_model::deposit::SCHEMA_CHANGE_RECORD_DEPOSIT_PROFILE,
                ..
            }) => continue,
            Some(ControlPayload::SchemaChange {
                kind: 12 | 14..=22, ..
            }) => {
                // Closing and FX routes, native subledger designations,
                // account roles, dimension values, requirements and closes,
                // Canon rule versions, lot policies and asset schedules
                // change no account membership. Validate the
                // complete canonical chart history before treating one as an
                // unrelated control; a malformed control is not skippable.
                fa_journal::chart::read_at(db, book, journal.through_seq)?;
                continue;
            }
            _ => {
                return Ok(Err(invalid("chart install lacks its recorded chart body")));
            }
        };
        let declared =
            match statement_chart_accounts(canonical_bytes, book.book_id, leaf.envelope.commit_seq)
            {
                Ok(accounts) => accounts,
                Err(error) => {
                    return Ok(Err(invalid(format!(
                        "chart install {:032x} does not decode canonically: {error}",
                        leaf.vid.0
                    ))));
                }
            };
        let mut accounts = Vec::new();
        for account in declared {
            cx.checkpoint().map_err(BookError::Context)?;
            if db
                .vertex_at(account.vid, certificate.known_at)
                .map_err(fa_journal::KernelError::from)?
                .is_some()
            {
                return Ok(Err(invalid(format!(
                    "chart install {:032x} rebinds existing account `{}`",
                    leaf.vid.0, account.code
                ))));
            }
            // Both snapshots must retain the declared identity and metadata;
            // a coincident SchemaChange cannot excuse an unrelated row edit.
            for at in [leaf.envelope.commit_seq, journal.through_seq] {
                let row = db
                    .vertex_at(account.vid, at)
                    .map_err(fa_journal::KernelError::from)?;
                let agrees = row.as_ref().is_some_and(|row| {
                    row.labels.contains(&label::ACCOUNT)
                        && row.created_at == leaf.envelope.commit_seq
                        && bytes(row, property::BOOK_ID, "chart account book")
                            .is_ok_and(|id| id == book.book_id.0)
                        && AccountRow::decode(row).is_ok_and(|actual| actual == account)
                });
                if !agrees {
                    return Ok(Err(invalid(format!(
                        "chart install {:032x} does not bind account `{}` at sequence {}",
                        leaf.vid.0, account.code, at.0
                    ))));
                }
            }
            accounts.push(fa_statements::Account {
                id: account.vid.0,
                code: account.code,
                name: account.name,
                account_type: account.account_type,
                is_leaf: account.is_leaf,
            });
        }
        let mapped = match partition {
            StatementPartition::ByType(definition) => {
                fa_statements::map_accounts(definition, &accounts)
            }
            StatementPartition::ByCode(definition) => {
                fa_statements::custom::map_custom_accounts(definition, &accounts)
            }
        };
        let mappings = match mapped {
            Ok(mappings) => mappings,
            Err(error) => {
                return Ok(Err(invalid(format!(
                    "the later chart does not satisfy the statement partition: {error}"
                ))));
            }
        };
        if !mappings.is_empty() {
            chart_entries.insert(leaf.vid);
        }
        for mapping in mappings {
            if !mapped_ids.insert(mapping.account.id) {
                return Ok(Err(invalid(
                    "later chart installs repeat a covered account",
                )));
            }
            additions.push(mapping);
        }
    }
    if additions.is_empty() {
        return Ok(Ok((None, chart_entries)));
    }
    let mut augmented = statement.clone();
    augmented.mappings.extend(additions);
    augmented.mappings.sort_by(|a, b| {
        a.account
            .code
            .cmp(&b.account.code)
            .then(a.account.id.cmp(&b.account.id))
    });
    let augmented = match (wrap, report) {
        (Some(wrap), _) => wrap(Box::new(augmented)),
        (None, ReportOutput::CustomStatement(report)) => {
            let mut report = report.clone();
            report.statement = augmented;
            ReportOutput::CustomStatement(report)
        }
        _ => return Ok(Err(invalid("statement partition has no matching output"))),
    };
    Ok(Ok((Some(augmented), chart_entries)))
}

/// How a statement-shaped report assigns covered leaves to lines: a
/// registered definition by account type, a regulatory schedule by code.
#[derive(Clone, Copy)]
enum StatementPartition<'a> {
    ByType(&'a fa_statements::StatementDefinition),
    ByCode(&'a fa_statements::custom::CustomStatementDefinition),
}

/// Read the existing `genesis::install_chart` body, including its additive
/// limit and period-scope tails. `AccountSpec::canonical` is private to the
/// journal crate; this reader preserves that exact format and verifies its
/// canonical re-encoding rather than inventing another chart representation.
fn statement_chart_accounts(
    body: &[u8],
    book_id: Id128,
    recorded_at: CommitSeq,
) -> Result<Vec<AccountRow>, fa_model::DecodeError> {
    use fa_journal::genesis::UnitPolicy;
    use fa_journal::limit::{BalanceLimit, LimitScope};

    let mut r = Reader::new(body);
    let bound = fa_model::limits::MAX_SCHEMA_CHANGE_BYTES;
    if body.len() > bound {
        return Err(r.invalid("bounded chart body"));
    }
    // Even an account with a one-byte code and an empty name needs 21 bytes.
    let count = r.count(bound / 21, "chart accounts")?;
    let mut accounts: Vec<AccountRow> = Vec::new();
    let mut parents = Vec::new();
    let mut indices = BTreeMap::new();
    for index in 0..count {
        let code = r.str(64, "chart account code")?.to_string();
        if code.is_empty() || indices.insert(code.clone(), index).is_some() {
            return Err(r.invalid("unique nonempty chart account code"));
        }
        let name = r.str(bound, "chart account name")?.to_string();
        let account_type = r.u8("chart account type")?;
        if !fa_model::AccountType(account_type).is_registered() {
            return Err(r.invalid("registered chart account type"));
        }
        let normal_balance = r.u8("chart normal balance")?;
        let is_leaf = r.bool("chart posting")?;
        let unit_policy = match r.i64("chart unit policy")? {
            -1 => UnitPolicy::AnyCurrency,
            -2 => UnitPolicy::AnyUnit,
            value => UnitPolicy::Single(fa_money::UnitId(
                u32::try_from(value).map_err(|_| r.invalid("chart unit policy"))?,
            )),
        };
        parents.push(r.opt("chart parent", |r| {
            Ok(r.str(64, "chart parent code")?.to_string())
        })?);
        accounts.push(AccountRow {
            vid: fa_model::account_vid(book_id, &code),
            code,
            name,
            account_type,
            normal_balance,
            is_leaf,
            unit_policy,
            limit: None,
            created_at: recorded_at,
        });
    }
    for parent in parents.iter().flatten() {
        if !indices
            .get(parent)
            .is_some_and(|index| !accounts[*index].is_leaf)
        {
            return Err(r.invalid("declared summary chart parent"));
        }
    }
    let mut limited = Vec::new();
    let mut period_scoped = Vec::new();
    if r.remaining() != 0 {
        let count = r.count(accounts.len(), "chart limits")?;
        if count == 0 {
            return Err(r.invalid("nonempty chart limit tail"));
        }
        for _ in 0..count {
            let code = r.str(64, "limited account code")?;
            let index = *indices
                .get(code)
                .ok_or_else(|| r.invalid("declared limited account"))?;
            if limited.last().is_some_and(|previous| *previous >= index) {
                return Err(r.invalid("chart limit order"));
            }
            let limit = BalanceLimit {
                lower: r.opt("chart lower bound", |r| r.i128("lower bound"))?,
                upper: r.opt("chart upper bound", |r| r.i128("upper bound"))?,
                scope: LimitScope::Lifetime,
            };
            if !limit.is_well_formed()
                || !accounts[index].is_leaf
                || !matches!(accounts[index].unit_policy, UnitPolicy::Single(_))
            {
                return Err(r.invalid("chart limit on a single-unit leaf"));
            }
            accounts[index].limit = Some(limit);
            limited.push(index);
        }
        if r.remaining() != 0 {
            let count = r.count(limited.len(), "period-scoped chart limits")?;
            if count == 0 {
                return Err(r.invalid("nonempty chart period-scope tail"));
            }
            for _ in 0..count {
                let code = r.str(64, "period-scoped account code")?;
                let index = *indices
                    .get(code)
                    .ok_or_else(|| r.invalid("declared period-scoped account"))?;
                if period_scoped
                    .last()
                    .is_some_and(|previous| *previous >= index)
                {
                    return Err(r.invalid("chart period-scope order"));
                }
                let Some(limit) = &mut accounts[index].limit else {
                    return Err(r.invalid("period scope requires a chart limit"));
                };
                limit.scope = LimitScope::Period;
                period_scoped.push(index);
            }
        }
    }
    r.finish()?;
    let mut w = Writer::new();
    w.list(
        &accounts.iter().zip(&parents).collect::<Vec<_>>(),
        |w, (a, parent)| {
            let unit_policy = match a.unit_policy {
                UnitPolicy::Single(unit) => i64::from(unit.0),
                UnitPolicy::AnyCurrency => -1,
                UnitPolicy::AnyUnit => -2,
            };
            w.str(&a.code)
                .str(&a.name)
                .u8(a.account_type)
                .u8(a.normal_balance)
                .bool(a.is_leaf)
                .i64(unit_policy)
                .opt(parent.as_ref(), |w, code| {
                    w.str(code);
                });
        },
    );
    if !limited.is_empty() {
        w.u32(
            u32::try_from(limited.len())
                .map_err(|_| Reader::new(body).invalid("bounded chart limit encoding"))?,
        );
        for index in &limited {
            let account = &accounts[*index];
            let Some(limit) = account.limit.as_ref() else {
                return Err(Reader::new(body).invalid("decoded chart limit"));
            };
            w.str(&account.code)
                .opt(limit.lower.as_ref(), |w, value| {
                    w.i128(*value);
                })
                .opt(limit.upper.as_ref(), |w, value| {
                    w.i128(*value);
                });
        }
    }
    if !period_scoped.is_empty() {
        w.list(&period_scoped, |w, index| {
            w.str(&accounts[*index].code);
        });
    }
    let encoded = w
        .finish()
        .map_err(|_| Reader::new(body).invalid("canonical chart encoding"))?;
    if encoded != body {
        return Err(Reader::new(body).invalid("canonical chart bytes"));
    }
    Ok(accounts)
}

#[cfg(test)]
mod statement_chart_body_tests {
    use super::*;
    use fa_journal::limit::{BalanceLimit, LimitScope};

    fn original_chart_body() -> Vec<u8> {
        // The pre-limit AccountSpec wire layout, with a valid blank name.
        let mut w = Writer::new();
        w.u32(1)
            .str("5999")
            .str("")
            .u8(5)
            .u8(0)
            .bool(true)
            .i64(0)
            .u8(0);
        w.finish().unwrap()
    }

    #[test]
    fn chart_reader_preserves_existing_body_and_additive_limit_tails() {
        let book = Id128([9; 16]);
        let at = CommitSeq(7);
        let mut body = original_chart_body();
        let accounts = statement_chart_accounts(&body, book, at).unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0].vid, fa_model::account_vid(book, "5999"));
        assert_eq!(accounts[0].created_at, at);
        assert!(accounts[0].name.is_empty());
        assert_eq!(accounts[0].limit, None);

        let mut limit = Writer::new();
        limit.u32(1).str("5999").u8(0).u8(1).i128(200);
        body.extend(limit.finish().unwrap());
        assert_eq!(
            statement_chart_accounts(&body, book, at).unwrap()[0].limit,
            Some(BalanceLimit {
                lower: None,
                upper: Some(200),
                scope: LimitScope::Lifetime,
            })
        );
        let mut scope = Writer::new();
        scope.u32(1).str("5999");
        body.extend(scope.finish().unwrap());
        assert_eq!(
            statement_chart_accounts(&body, book, at).unwrap()[0]
                .limit
                .unwrap()
                .scope,
            LimitScope::Period
        );
    }

    #[test]
    fn chart_reader_refuses_truncation_duplicates_and_unbound_limit_tails() {
        let body = original_chart_body();
        let parse = |bytes: &[u8]| statement_chart_accounts(bytes, Id128([9; 16]), CommitSeq(7));
        for length in 0..body.len() {
            assert!(parse(&body[..length]).is_err(), "prefix {length}");
        }
        let mut empty_tail = body.clone();
        empty_tail.extend(0u32.to_le_bytes());
        assert!(parse(&empty_tail).is_err());
        let mut duplicate = 2u32.to_le_bytes().to_vec();
        duplicate.extend_from_slice(&body[4..]);
        duplicate.extend_from_slice(&body[4..]);
        assert!(parse(&duplicate).is_err());
        let mut foreign_limit = Writer::new();
        foreign_limit
            .fixed(&body)
            .u32(1)
            .str("6000")
            .u8(0)
            .u8(1)
            .i128(200);
        assert!(parse(&foreign_limit.finish().unwrap()).is_err());
        let mut trailing = body;
        trailing.push(255);
        assert!(parse(&trailing).is_err());
        assert!(parse(&vec![0; fa_model::limits::MAX_SCHEMA_CHANGE_BYTES + 1]).is_err());
    }
}

/// The current chart installer only creates fresh identities; it does not
/// declare an update to an existing account. A different current value for
/// metadata actually emitted by the report is therefore unsupported rebinding,
/// even when an unrelated SchemaChange entry shares the write's sequence.
fn unchanged_account_metadata<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    report: &ReportOutput,
    at: CommitSeq,
) -> Outcome<()> {
    let trial_balance_metadata = |report: &TrialBalance| -> BTreeMap<VId, AccountMetadata> {
        report
            .rows
            .iter()
            .map(|row| {
                (
                    row.account,
                    AccountMetadata::TrialBalance {
                        code: row.code.clone(),
                        name: row.name.clone(),
                        account_type: row.account_type.0,
                    },
                )
            })
            .collect()
    };
    let accounts: BTreeMap<VId, AccountMetadata> = match report {
        ReportOutput::TrialBalance(report) => trial_balance_metadata(report),
        ReportOutput::FunctionalTrialBalance(report) => report
            .accounts
            .iter()
            .map(|(vid, row)| (*vid, AccountMetadata::Complete(row.clone())))
            .collect(),
        ReportOutput::DimensionTrialBalance(report) => {
            trial_balance_metadata(&report.trial_balance)
        }
        ReportOutput::ExplainBalance(report) => BTreeMap::from([(
            report.account,
            AccountMetadata::Complete(report.account_row.clone()),
        )]),
        ReportOutput::OpenItems(report) => report
            .accounts
            .iter()
            .map(|(vid, row)| (*vid, AccountMetadata::Complete(row.clone())))
            .collect(),
        ReportOutput::Statement(report)
        | ReportOutput::FunctionalStatement(report)
        | ReportOutput::RegulatorySchedule(report) => statement_account_metadata([report.as_ref()]),
        ReportOutput::CustomStatement(report) => statement_account_metadata([&report.statement]),
        ReportOutput::Consolidation(report) => {
            statement_account_metadata([&report.run.balance_sheet, &report.run.income_statement])
        }
        ReportOutput::FunctionalConsolidation(report) => statement_account_metadata([
            &report.group.run.balance_sheet,
            &report.group.run.income_statement,
        ]),
    };
    for (vid, expected) in accounts {
        cx.checkpoint().map_err(BookError::Context)?;
        let Some(row) = db
            .vertex_at(vid, at)
            .map_err(fa_journal::KernelError::from)?
            .filter(|row| row.labels.contains(&label::ACCOUNT))
        else {
            return Ok(Err(invalid(format!(
                "certified account {:032x} was retired or rebound",
                vid.0
            ))));
        };
        let row = match AccountRow::decode(&row) {
            Ok(row) => row,
            Err(error) => {
                return Ok(Err(invalid(format!(
                    "certified account {:032x} no longer decodes: {error}",
                    vid.0
                ))));
            }
        };
        if expected.project(row) != expected {
            return Ok(Err(invalid(format!(
                "displayed metadata for account {:032x} changed without a supported journaled chart update",
                vid.0
            ))));
        }
    }
    Ok(Ok(()))
}

/// The displayed metadata of every account the statements map.
fn statement_account_metadata<'a>(
    statements: impl IntoIterator<Item = &'a fa_statements::Statement>,
) -> BTreeMap<VId, AccountMetadata> {
    statements
        .into_iter()
        .flat_map(|statement| &statement.mappings)
        .map(|mapping| {
            (
                VId(mapping.account.id),
                AccountMetadata::Statement {
                    code: mapping.account.code.clone(),
                    name: mapping.account.name.clone(),
                    account_type: mapping.account.account_type,
                    is_leaf: mapping.account.is_leaf,
                },
            )
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum AccountMetadata {
    TrialBalance {
        code: String,
        name: String,
        account_type: u8,
    },
    Complete(AccountRow),
    Statement {
        code: String,
        name: String,
        account_type: u8,
        is_leaf: bool,
    },
}

impl AccountMetadata {
    fn project(&self, row: AccountRow) -> Self {
        match self {
            Self::TrialBalance { .. } => Self::TrialBalance {
                code: row.code,
                name: row.name,
                account_type: row.account_type,
            },
            Self::Complete(_) => Self::Complete(row),
            Self::Statement { .. } => Self::Statement {
                code: row.code,
                name: row.name,
                account_type: row.account_type,
                is_leaf: row.is_leaf,
            },
        }
    }
}

/// A consolidation reads ownership only between its members on the selected
/// period's last day, and only the roles used by Concordat. Recording a future
/// stake, a third party relationship or another workflow's role does not
/// supersede that period's report.
fn consolidation_control_selected(
    effective_through: DateDay,
    entity_codes: &BTreeMap<Id128, String>,
    control: Option<&ControlPayload>,
) -> Result<bool, BookError> {
    let Some(ControlPayload::SchemaChange {
        kind,
        canonical_bytes,
    }) = control
    else {
        return Ok(false);
    };
    match *kind {
        // Chart membership and lifecycle controls remain relevant: even a
        // zero balance account can change the statements' mandatory mapping.
        1..=4 => Ok(true),
        fa_model::rea::SCHEMA_CHANGE_RECORD_RELATIONSHIP => {
            let relationship =
                fa_model::RelationshipSpec::decode(canonical_bytes).map_err(|error| {
                    fa_journal::KernelError::Corrupt(format!(
                        "consolidation ownership control: {error}"
                    ))
                })?;
            Ok(
                matches!(relationship.kind, fa_model::RelationshipKind::Owns { .. })
                    && relationship.is_active_on(effective_through)
                    && entity_codes.contains_key(&Id128(relationship.from.0.to_be_bytes()))
                    && entity_codes.contains_key(&Id128(relationship.to.0.to_be_bytes())),
            )
        }
        fa_journal::account_role::SCHEMA_CHANGE_ACCOUNT_ROLE => {
            let role = fa_journal::account_role::AccountRoleSpec::decode(canonical_bytes)?;
            Ok(crate::consolidation::CONSOLIDATION_ROLES.contains(&role.role.as_str()))
        }
        _ => Ok(false),
    }
}

pub(crate) fn selected(
    book: &BookContext,
    selection: &ReportSelection,
    report: &ReportOutput,
    entry: &Entry,
    entries: &BTreeMap<VId, Entry>,
) -> Result<bool, BookError> {
    // A control's nominal date is not a contribution. Releases and migration
    // activation are checked explicitly by their targets in the caller. A
    // consolidation also reads the chart, the active group ownership edges,
    // and the account roles those schema controls journal.
    if entry.proposal.legs.is_empty() || fa_notary::journal::is_undated(entry.proposal.class) {
        return match (selection, report) {
            (ReportSelection::Consolidation { .. }, ReportOutput::Consolidation(report)) => {
                consolidation_control_selected(
                    report.effective_through,
                    &report.entity_codes,
                    entry.proposal.control.as_ref(),
                )
            }
            (
                ReportSelection::FunctionalConsolidation { .. },
                ReportOutput::FunctionalConsolidation(report),
            ) => consolidation_control_selected(
                report.group.effective_through,
                &report.group.entity_codes,
                entry.proposal.control.as_ref(),
            ),
            // A value created under the reported one: its rerun folds it.
            (
                ReportSelection::DimensionTrialBalance { .. },
                ReportOutput::DimensionTrialBalance(report),
            ) => match entry.proposal.control.as_ref() {
                Some(ControlPayload::SchemaChange {
                    kind: fa_journal::dimension::SCHEMA_CHANGE_DIMENSION_VALUE,
                    canonical_bytes,
                }) => {
                    let spec = fa_journal::dimension::DimensionValueSpec::decode(canonical_bytes)?;
                    Ok(spec.dimension == report.dimension && report.values.contains(&spec.code))
                }
                _ => Ok(false),
            },
            _ => Ok(false),
        };
    }
    match (selection, report) {
        // Every member's posted stock through the period's last day, of
        // which the period's activity is part.
        (ReportSelection::Consolidation { .. }, ReportOutput::Consolidation(report)) => {
            return Ok(entry.proposal.class != EntryClass::PENDING
                && entry.proposal.effective_date <= report.effective_through);
        }
        (
            ReportSelection::FunctionalConsolidation { .. },
            ReportOutput::FunctionalConsolidation(report),
        ) => {
            return Ok(entry.proposal.class != EntryClass::PENDING
                && entry.proposal.effective_date <= report.group.effective_through);
        }
        (ReportSelection::OpenItems { account }, ReportOutput::OpenItems(_)) => {
            return open_item_selected(entry, entries, *account);
        }
        (ReportSelection::TrialBalance(_), ReportOutput::TrialBalance(report)) => {
            if let Some(through) = report.effective_through {
                return Ok(entry.proposal.effective_date <= through);
            }
        }
        (
            ReportSelection::FunctionalTrialBalance(_),
            ReportOutput::FunctionalTrialBalance(report),
        ) => {
            if let Some(through) = report.effective_through {
                return Ok(entry.proposal.effective_date <= through);
            }
        }
        (
            ReportSelection::DimensionTrialBalance { .. },
            ReportOutput::DimensionTrialBalance(report),
        ) => {
            if !entry
                .proposal
                .legs
                .iter()
                .any(|leg| report.tags(book.book_id, leg))
            {
                return Ok(false);
            }
            if let Some(through) = report.trial_balance.effective_through {
                return Ok(entry.proposal.effective_date <= through);
            }
        }
        (ReportSelection::ExplainBalance { .. }, ReportOutput::ExplainBalance(_)) => {}
        (ReportSelection::Statement(_), ReportOutput::Statement(_))
        | (ReportSelection::FunctionalStatement(_), ReportOutput::FunctionalStatement(_))
        | (ReportSelection::RegulatorySchedule(_), ReportOutput::RegulatorySchedule(_))
        | (ReportSelection::CustomStatement(_), ReportOutput::CustomStatement(_)) => {
            let report = match report {
                ReportOutput::Statement(statement)
                | ReportOutput::FunctionalStatement(statement)
                | ReportOutput::RegulatorySchedule(statement) => statement.as_ref(),
                ReportOutput::CustomStatement(report) => &report.statement,
                _ => unreachable!("matched statement output"),
            };
            let Some((kind, _, _)) = selection.statement_columns() else {
                return Err(fa_journal::KernelError::Corrupt(
                    "a statement certificate lacks its statement columns".into(),
                )
                .into());
            };
            if entry.proposal.class == EntryClass::PENDING {
                return Ok(false);
            }
            if !entry.proposal.legs.iter().any(|leg| {
                report
                    .mappings
                    .iter()
                    .any(|mapping| mapping.account.id == leg.account_ref.0)
            }) {
                return Ok(false);
            }
            if kind.basis() == fa_statements::Basis::Stock {
                return Ok(report
                    .columns
                    .iter()
                    .any(|column| entry.proposal.effective_date <= column.effective_through));
            }
            let mut original = entry;
            let mut seen = BTreeSet::new();
            loop {
                if kind.excluded_classes().contains(&original.proposal.class) {
                    return Ok(false);
                }
                if original.proposal.class != EntryClass::REVERSAL {
                    break;
                }
                let [supersession] = original.proposal.supersession.as_slice() else {
                    return Err(fa_journal::KernelError::Corrupt(
                        "statement status reversal lacks its single target".into(),
                    )
                    .into());
                };
                if supersession.kind != fa_model::SupersessionKind::Reverses
                    || !seen.insert(supersession.target.vid)
                {
                    return Err(fa_journal::KernelError::Corrupt(
                        "statement status reversal lineage is invalid or cyclic".into(),
                    )
                    .into());
                }
                let target = entries.get(&supersession.target.vid).ok_or_else(|| {
                    fa_journal::KernelError::Corrupt(
                        "statement status reversal target is absent from the journal".into(),
                    )
                })?;
                if target.entry_digest != supersession.target.entry_digest {
                    return Err(fa_journal::KernelError::Corrupt(
                        "statement status reversal target digest differs from its lineage".into(),
                    )
                    .into());
                }
                original = target;
            }
        }
        _ => {
            return Err(fa_journal::KernelError::Corrupt(
                "certificate selector and report kind disagree".into(),
            )
            .into());
        }
    }
    let date = entry.proposal.effective_date;
    let fy = book
        .calendar
        .fiscal_year_of(date)
        .map_err(fa_journal::KernelError::from)?;
    let calendar = book
        .calendar
        .periods_for_year(fy)
        .map_err(fa_journal::KernelError::from)?;
    let period = fa_time::resolve_period(
        &calendar,
        date,
        entry
            .proposal
            .effective_period
            .as_ref()
            .map(|p| p.code.as_str()),
    )
    .map_err(|e| {
        BookError::Kernel(fa_journal::KernelError::Corrupt(format!(
            "certificate status period: {e:?}"
        )))
    })?;
    Ok(match selection {
        ReportSelection::TrialBalance(TrialBalanceSelection::Activity(periods))
        | ReportSelection::FunctionalTrialBalance(TrialBalanceSelection::Activity(periods))
        | ReportSelection::DimensionTrialBalance {
            selection: TrialBalanceSelection::Activity(periods),
            ..
        } => periods.binary_search(&period.code).is_ok(),
        // The explanation also names the entire period's fold digest and
        // watermark, so a contribution to another account changes its output.
        ReportSelection::ExplainBalance {
            period: selected, ..
        } => *selected == period.code,
        ReportSelection::Statement(_)
        | ReportSelection::FunctionalStatement(_)
        | ReportSelection::RegulatorySchedule(_)
        | ReportSelection::CustomStatement(_) => {
            selection
                .statement_columns()
                .is_some_and(|(_, periods, comparative)| {
                    periods.binary_search(&period.code).is_ok()
                        || comparative.binary_search(&period.code).is_ok()
                })
        }
        _ => false,
    })
}

pub(crate) fn open_item_selected(
    entry: &Entry,
    entries: &BTreeMap<VId, Entry>,
    account: Option<VId>,
) -> Result<bool, BookError> {
    let mut original = entry;
    let mut seen = BTreeSet::new();
    while original.proposal.class == EntryClass::REVERSAL {
        let [supersession] = original.proposal.supersession.as_slice() else {
            return Err(fa_journal::KernelError::Corrupt(
                "open-item status reversal lacks its single target".into(),
            )
            .into());
        };
        if supersession.kind != fa_model::SupersessionKind::Reverses
            || !seen.insert(supersession.target.vid)
        {
            return Err(fa_journal::KernelError::Corrupt(
                "open-item status reversal lineage is invalid or cyclic".into(),
            )
            .into());
        }
        original = entries.get(&supersession.target.vid).ok_or_else(|| {
            fa_journal::KernelError::Corrupt(
                "open-item status reversal target is absent from the journal".into(),
            )
        })?;
    }
    Ok(carries_open_items(original)
        && account.is_none_or(|account| {
            original
                .proposal
                .legs
                .iter()
                .any(|leg| leg.account_ref == account)
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fa_journal::{BalanceLimit, LimitScope, UnitPolicy};
    use fa_model::{EntryPayload, EntryRef, Erasable, LegPayload, Oid, SealKey, Supersession};
    use fa_money::{Amount, Side, UnitId, UnitRegistry};

    fn account() -> AccountRow {
        AccountRow {
            vid: VId(9),
            code: "AR".into(),
            name: "Receivables".into(),
            account_type: 1,
            normal_balance: 0,
            is_leaf: true,
            unit_policy: UnitPolicy::Single(UnitId(0)),
            limit: None,
            created_at: CommitSeq(2),
        }
    }

    fn context() -> BookContext {
        BookContext {
            book_id: Id128([9; 16]),
            calendar: fa_time::FiscalCalendar::monthly("cy", 1, 1).unwrap(),
            units: UnitRegistry::embedded().unwrap(),
            seal_key: SealKey([1; 32]),
            symbols: fa_model::SymbolTable::compiled(),
        }
    }

    fn posting(class: EntryClass, key: u8) -> Entry {
        let legs = vec![
            LegPayload::simple(Side::Debit, VId(1), Amount::new(UnitId(0), 100)),
            LegPayload::simple(Side::Credit, VId(2), Amount::new(UnitId(0), 100)),
        ];
        EntryPayload {
            schema_minor: fa_model::entry::SCHEMA_MINOR,
            book_id: Id128([9; 16]),
            branch_id: Id128::TRUNK,
            class,
            effective_date: DateDay::from_ymd(2026, 1, 15).unwrap(),
            document_date: None,
            description: Erasable::seal(
                &"Certificate selection fixture".to_string(),
                None,
                &SealKey([1; 32]),
                [2; 32],
                [3; 24],
            ),
            effective_period: None,
            unit_totals: EntryPayload::fold_unit_totals(&legs).unwrap(),
            legs,
            control: None,
            base_totals: None,
            idempotency_key: vec![key],
            origin: EntryOrigin::Intent {
                intent_oid: Oid([key; 32]),
                intent_kind: 1,
            },
            principal_ref: VId(77),
            session_ref: None,
            evidence: Vec::new(),
            supersession: Vec::new(),
            pending: (class == EntryClass::PENDING).then_some(fa_model::Pending {
                resolution_of: None,
                disposition: None,
                timeout_ns: None,
            }),
            external_ids: Vec::new(),
            extensions: Vec::new(),
            tags: Vec::new(),
        }
        .seal(Vec::new(), None)
        .unwrap()
    }

    fn reversal(target: &Entry, vid: VId, key: u8) -> Entry {
        let mut proposal = posting(EntryClass::ORIGINAL, key).proposal;
        proposal.class = EntryClass::REVERSAL;
        proposal.legs = target.proposal.legs.clone();
        for leg in &mut proposal.legs {
            leg.side = match leg.side {
                Side::Debit => Side::Credit,
                Side::Credit => Side::Debit,
            };
        }
        proposal.unit_totals = EntryPayload::fold_unit_totals(&proposal.legs).unwrap();
        proposal.supersession.push(Supersession {
            target: EntryRef {
                vid,
                entry_digest: target.entry_digest,
            },
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 1,
        });
        proposal.seal(Vec::new(), None).unwrap()
    }

    fn wire_fixture(
        selection: ReportSelection,
        time_selection: Option<fa_journal::InstantSelection>,
    ) -> ReportCertificate {
        ReportCertificate {
            book_id: Id128([1; 16]),
            branch_id: Id128::TRUNK,
            known_at: CommitSeq(7),
            time_selection,
            registry_digest: [2; 32],
            selection,
            journal_root: [3; 32],
            journal_leaves: 4,
            // This fixture pins the body layout only. End-to-end facade tests
            // supply all seven genuine native certificates and replay them.
            inputs: Vec::new(),
            output: vec![0xaa, 0xbb],
            output_digest: [5; 32],
            digest: [6; 32],
        }
    }

    #[test]
    fn trial_balance_v1_and_instant_v2_keep_their_original_body_layout() {
        let mut certificate = wire_fixture(TrialBalanceSelection::AsOf(DateDay(-2)).into(), None);
        let mut expected = CERTIFICATE_FORMAT.to_vec();
        for value in [REPLAY_SCOPE, AUTHORITY, OUTPUT_FORMAT] {
            expected.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            expected.extend_from_slice(value.as_bytes());
        }
        expected.extend_from_slice(&[1; 16]);
        expected.extend_from_slice(&Id128::TRUNK.0);
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.push(1); // Original AsOf selector tag; no report-kind envelope.
        expected.extend_from_slice(&(-2i32).to_le_bytes());
        expected.extend_from_slice(&[2; 32]);
        expected.extend_from_slice(&[3; 32]);
        expected.extend_from_slice(&4u64.to_le_bytes());
        expected.extend_from_slice(&0u32.to_le_bytes()); // Native input count.
        expected.extend_from_slice(&2u32.to_le_bytes());
        expected.extend_from_slice(&[0xaa, 0xbb]);
        expected.extend_from_slice(&[5; 32]);
        assert_eq!(certificate.body_bytes().unwrap(), expected);
        assert_eq!(certificate.format(), CERTIFICATE_FORMAT);

        let lower = fa_time::TimeObservation {
            recorded_at: 5,
            observed_utc_ns: 100,
            source: 0,
            monotonic_ok: true,
        };
        let upper = fa_time::TimeObservation {
            recorded_at: 10,
            observed_utc_ns: 200,
            source: 0,
            monotonic_ok: true,
        };
        let time = fa_journal::InstantSelection {
            resolution: fa_time::resolve_instant(&[lower, upper], 150, 12).unwrap(),
            lower_entry: VId(51),
            upper_entry: Some(VId(101)),
        };
        assert!(time.is_canonical());
        let mut time_bytes = Writer::new();
        write_time_selection(&mut time_bytes, &time);
        let time_bytes = time_bytes.finish().unwrap();
        certificate.known_at = CommitSeq(time.resolution.resolved_seq);
        let sequence_offset = CERTIFICATE_FORMAT.len()
            + [REPLAY_SCOPE, AUTHORITY, OUTPUT_FORMAT]
                .iter()
                .map(|value| 4 + value.len())
                .sum::<usize>()
            + 32;
        expected[sequence_offset..sequence_offset + 8]
            .copy_from_slice(&certificate.known_at.0.to_le_bytes());
        certificate.time_selection = Some(time.clone());
        expected[..CERTIFICATE_FORMAT.len()].copy_from_slice(INSTANT_CERTIFICATE_FORMAT);
        // V2 directly appends time evidence, without V3's option tag.
        expected.extend_from_slice(&time_bytes);
        assert_eq!(certificate.body_bytes().unwrap(), expected);
        assert_eq!(certificate.format(), INSTANT_CERTIFICATE_FORMAT);
        let mut reader = Reader::new(&time_bytes);
        assert_eq!(read_time_selection(&mut reader).unwrap(), time);
        reader.finish().unwrap();

        certificate.selection = ReportSelection::OpenItems {
            account: Some(VId(9)),
        };
        let with_time = certificate.body_bytes().unwrap();
        assert_eq!(certificate.format(), REPORT_CERTIFICATE_FORMAT);
        let time_offset = with_time.len() - time_bytes.len() - 1;
        assert_eq!(with_time[time_offset], 1);
        let mut reader = Reader::new(&with_time[time_offset..]);
        assert_eq!(reader.opt("time", read_time_selection).unwrap(), Some(time));
        reader.finish().unwrap();
        certificate.time_selection = None;
        let without_time = certificate.body_bytes().unwrap();
        assert_eq!(
            &without_time[..without_time.len() - 1],
            &with_time[..time_offset]
        );
        assert_eq!(without_time.last(), Some(&0));
    }

    /// fa-t8gk planted negatives: the v2 closure binds only the registries the
    /// report's computation reads, ignores a comment-only and layout-only
    /// registry edit (the v1 raw-text closure did not), and a changed normal
    /// side always moves it.
    #[test]
    fn registry_closure_binds_canonical_content_not_file_text() {
        let trial = ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(DateDay(0)));
        let open_items = ReportSelection::OpenItems { account: None };
        let statement = ReportSelection::from(crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P01".into()],
            comparative: Vec::new(),
        });
        let explain = ReportSelection::ExplainBalance {
            account: VId(9),
            period: "FY2026-P01".into(),
        };
        // Trial balance, open items, and statements bind the same 4 read
        // registries (account_types, entry_classes, units, foundations); only
        // balance explanations also bind reason_codes.
        assert_eq!(
            report_registries(&trial)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>(),
            vec!["account_types", "entry_classes", "units", "foundations"]
        );
        assert_eq!(report_registries(&open_items), report_registries(&trial));
        assert_eq!(report_registries(&statement), report_registries(&trial));
        assert_eq!(
            report_registries(&explain)
                .into_iter()
                .map(|(n, _)| n)
                .collect::<Vec<_>>(),
            vec![
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "reason_codes",
            ]
        );
        assert_eq!(
            registry_digest(&trial).unwrap(),
            registry_digest(&open_items).unwrap()
        );
        assert_eq!(
            registry_digest(&trial).unwrap(),
            registry_digest(&statement).unwrap()
        );
        assert_ne!(
            registry_digest(&trial).unwrap(),
            registry_digest(&explain).unwrap()
        );

        fn with<'a>(
            name: &str,
            text: &'a str,
            sources: Vec<(&'a str, &'a str)>,
        ) -> Vec<(&'a str, &'a str)> {
            sources
                .into_iter()
                .map(|(n, t)| (n, if n == name { text } else { t }))
                .collect()
        }
        let (name, text) = REPORT_REGISTRIES[0];
        assert_eq!(name, "account_types");
        let annotated: String = text
            .lines()
            .map(|line| format!("{line}   # a reviewer's note\n\n"))
            .collect();
        let restyled = format!("# a new header comment\n{annotated}");
        assert_ne!(restyled, text);
        let first = text
            .lines()
            .position(|l| l.trim() == "normal_balance = 0")
            .expect("an account type with a debit normal side");
        let flipped: String = text
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == first {
                    "normal_balance = 1\n".to_string()
                } else {
                    format!("{l}\n")
                }
            })
            .collect();
        for selection in [&trial, &open_items, &statement, &explain] {
            let current = registry_digest(selection).unwrap();
            let v2 = |sources: &[(&str, &str)]| {
                canonical_closure(b"fa:report-registry-closure:v2", sources).unwrap()
            };
            assert_eq!(v2(&report_registries(selection)), current);
            assert_eq!(
                v2(&with(name, &restyled, report_registries(selection))),
                current
            );
            assert_ne!(
                v2(&with(name, &flipped, report_registries(selection))),
                current
            );
            assert_ne!(current, legacy_v2_registry_digest(selection).unwrap());
            // The defect: the raw-text closure moved on the same cosmetic edit.
            let raw = |sources: &[(&str, &str)]| {
                let leaves: Vec<(&str, [u8; 32])> = sources
                    .iter()
                    .map(|(n, t)| (*n, digest(b"fa:report-registry:v1", t.as_bytes())))
                    .collect();
                registry_closure(b"fa:report-registry-closure:v1", &leaves)
            };
            assert_eq!(
                raw(&legacy_report_registries(selection)),
                legacy_registry_digest(selection)
            );
            assert_ne!(
                raw(&with(name, &restyled, legacy_report_registries(selection))),
                legacy_registry_digest(selection)
            );
            assert_ne!(current, legacy_registry_digest(selection));
        }
        // Every embedded registry (current and legacy) parses, so no certificate is refused for it.
        for (name, text) in legacy_report_registries(&explain) {
            canonical_registry_digest(name, text).unwrap();
        }
    }

    #[test]
    fn report_selectors_round_trip_without_reinterpreting_legacy_tags() {
        let legacy = [
            TrialBalanceSelection::Periods(vec!["FY2026-P01".into()]),
            TrialBalanceSelection::AsOf(DateDay(20_000)),
            TrialBalanceSelection::Activity(vec!["FY2026-A1".into()]),
        ];
        for selection in legacy {
            let report = ReportSelection::from(selection.clone());
            let mut writer = Writer::new();
            report.write(&mut writer).unwrap();
            let bytes = writer.finish().unwrap();
            for version in [1, 2] {
                let mut reader = Reader::new(&bytes);
                assert_eq!(ReportSelection::read(&mut reader, version).unwrap(), report);
                reader.finish().unwrap();
            }
        }
        for selection in [
            ReportSelection::ExplainBalance {
                account: VId(9),
                period: "FY2026-A1".into(),
            },
            ReportSelection::OpenItems { account: None },
            ReportSelection::OpenItems {
                account: Some(VId(9)),
            },
        ] {
            let mut writer = Writer::new();
            selection.write(&mut writer).unwrap();
            let bytes = writer.finish().unwrap();
            let mut reader = Reader::new(&bytes);
            assert_eq!(ReportSelection::read(&mut reader, 3).unwrap(), selection);
            reader.finish().unwrap();
            // A new format must not accept the old selector and reconstruct
            // a different header while validating the old content digest.
            assert!(ReportSelection::read(&mut Reader::new(&bytes), 4).is_err());
            let certificate = wire_fixture(selection, None);
            assert_eq!(certificate.format(), REPORT_CERTIFICATE_FORMAT);
            assert_eq!(certificate.body_bytes().unwrap().last(), Some(&0));
        }
        let mut bad = Writer::new();
        bad.u8(0).u128(9).str(&"P".repeat(129));
        assert!(ReportSelection::read(&mut Reader::new(&bad.finish().unwrap()), 3).is_err());
        assert!(
            !ReportSelection::ExplainBalance {
                account: VId(9),
                period: String::new(),
            }
            .is_canonical()
        );
        assert!(ReportSelection::read(&mut Reader::new(&[255]), 3).is_err());
    }

    #[test]
    fn statement_certificates_pin_the_definition_and_reserve_v4() {
        let selection = ReportSelection::from(crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P03".into()],
            comparative: vec!["FY2025-P03".into()],
        });
        let mut writer = Writer::new();
        selection.write(&mut writer).unwrap();
        let bytes = writer.finish().unwrap();
        let mut reader = Reader::new(&bytes);
        assert_eq!(ReportSelection::read(&mut reader, 4).unwrap(), selection);
        reader.finish().unwrap();
        assert!(ReportSelection::read(&mut Reader::new(&bytes), 3).is_err());
        let certificate = wire_fixture(selection, None);
        assert_eq!(certificate.format(), STATEMENT_CERTIFICATE_FORMAT);
        assert_eq!(certificate.output_format(), "fa:statement:v1");
        let original = certificate.body_bytes().unwrap();
        assert_eq!(original.last(), Some(&0));
        let mut changed = certificate.clone();
        if let ReportSelection::Statement(selection) = &mut changed.selection {
            selection.definition =
                crate::StatementDefinition::embedded("income-statement").unwrap();
        }
        assert_ne!(changed.body_bytes().unwrap(), original);
        let mut changed = certificate;
        if let ReportSelection::Statement(selection) = &mut changed.selection {
            selection.comparative = vec!["FY2024-P03".into()];
        }
        assert_ne!(changed.body_bytes().unwrap(), original);
    }

    #[test]
    fn offline_statement_export_binds_exact_registry_documents_and_book_units() {
        let selection = ReportSelection::from(crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P03".into()],
            comparative: Vec::new(),
        });
        let mut certificate = wire_fixture(selection, None);
        certificate.registry_digest = registry_digest(&certificate.selection).unwrap();
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let documents = offline_report_registries(&certificate, &units).unwrap();
        assert_eq!(
            documents
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["account_types", "entry_classes", "units", "foundations"]
        );
        let leaves = documents
            .iter()
            .map(|(name, bytes)| {
                (
                    name.as_str(),
                    digest(b"fa:registry-canonical-digest:v1", bytes),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            registry_closure(b"fa:report-registry-closure:v2", &leaves),
            certificate.registry_digest
        );
        let mut subset = fa_money::UnitRegistry::empty();
        subset
            .register(units.iter().next().unwrap().1.clone())
            .unwrap();
        assert_eq!(
            offline_report_registries(&certificate, &subset)
                .unwrap_err()
                .code,
            fa_notary::code::SCOPE_UNSUPPORTED
        );
        // Cardinality and unit codes are not sufficient: the same ID with a
        // changed scale would reinterpret every historical amount.
        let mut changed = fa_money::UnitRegistry::empty();
        for (id, unit) in units.iter() {
            let mut unit = unit.clone();
            if id.0 == 0 {
                unit.scale = 3;
            }
            changed.register(unit).unwrap();
        }
        assert_eq!(
            offline_report_registries(&certificate, &changed)
                .unwrap_err()
                .code,
            fa_notary::code::SCOPE_UNSUPPORTED
        );
        certificate.registry_digest = legacy_v2_registry_digest(&certificate.selection).unwrap();
        assert_eq!(
            offline_report_registries(&certificate, &units)
                .unwrap_err()
                .code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE
        );
    }

    #[test]
    fn offline_roll_forward_source_keeps_exact_units_and_narrow_stock_profile() {
        let mut certificate = wire_fixture(
            ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(DateDay(20_000))),
            None,
        );
        certificate.registry_digest = registry_digest(&certificate.selection).unwrap();
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let documents = offline_report_registries(&certificate, &units).unwrap();
        assert_eq!(
            documents
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            ["account_types", "entry_classes", "units", "foundations"]
        );
        let mut subset = fa_money::UnitRegistry::empty();
        subset
            .register(units.iter().next().unwrap().1.clone())
            .unwrap();
        assert_eq!(
            offline_report_registries(&certificate, &subset)
                .unwrap_err()
                .code,
            fa_notary::code::SCOPE_UNSUPPORTED
        );
        let mut changed = fa_money::UnitRegistry::empty();
        for (id, unit) in units.iter() {
            let mut unit = unit.clone();
            if id.0 == 0 {
                unit.scale = 3;
            }
            changed.register(unit).unwrap();
        }
        assert_eq!(
            offline_report_registries(&certificate, &changed)
                .unwrap_err()
                .code,
            fa_notary::code::SCOPE_UNSUPPORTED
        );
        let mut branch = certificate.clone();
        branch.branch_id = Id128([2; 16]);
        assert!(offline_report_registries(&branch, &units).is_err());
        // Every trunk native trial-balance selection is portable since the
        // summary trial balances' outsider verification (fa-70h4), with the
        // same registry closure as the as-of stock; off trunk none is.
        for selection in [
            TrialBalanceSelection::Periods(vec!["FY2026-P03".into()]),
            TrialBalanceSelection::Activity(vec!["FY2026-P03".into()]),
        ] {
            let mut other = certificate.clone();
            other.selection = ReportSelection::TrialBalance(selection);
            assert_eq!(
                offline_report_registries(&other, &units).unwrap(),
                documents
            );
            other.branch_id = Id128([2; 16]);
            assert!(offline_report_registries(&other, &units).is_err());
        }
    }

    #[test]
    fn functional_statement_v5_separates_native_bytes_and_binds_valuation_sources() {
        let definition = crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("income-statement").unwrap(),
            periods: vec!["FY2026-P01".into()],
            comparative: vec!["FY2025-P01".into()],
        };
        let native = ReportSelection::Statement(Box::new(definition.clone()));
        let functional = ReportSelection::FunctionalStatement(Box::new(definition));
        let mut writer = Writer::new();
        functional.write(&mut writer).unwrap();
        let encoded = writer.finish().unwrap();
        let mut reader = Reader::new(&encoded);
        assert_eq!(ReportSelection::read(&mut reader, 5).unwrap(), functional);
        reader.finish().unwrap();
        for version in 1..5 {
            assert!(ReportSelection::read(&mut Reader::new(&encoded), version).is_err());
        }
        let native_inputs = statements(CommitSeq(7), &native);
        let functional_inputs = statements(CommitSeq(7), &functional);
        assert_eq!(functional_inputs[..INPUTS.len()], native_inputs);
        assert_eq!(functional_inputs.len(), native_inputs.len() + 1);
        assert!(
            functional_inputs
                .last()
                .unwrap()
                .contains("WHERE n.code = 'Rate'")
        );
        assert_eq!(
            report_registries(&functional)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            [
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "fx_laws",
                "rounding_laws"
            ],
        );
        assert_ne!(
            registry_digest(&functional).unwrap(),
            registry_digest(&native).unwrap()
        );
        let certificate = wire_fixture(functional, None);
        assert_eq!(
            certificate.format(),
            FUNCTIONAL_STATEMENT_CERTIFICATE_FORMAT
        );
        assert_eq!(
            certificate.output_format(),
            FUNCTIONAL_STATEMENT_OUTPUT_FORMAT
        );
        assert_eq!(certificate.body_bytes().unwrap().last(), Some(&0));
    }

    #[test]
    fn explanation_status_tracks_the_whole_period_and_special_period_identity() {
        let book = context();
        let mut report = ReportOutput::ExplainBalance(Box::new(BalanceExplanation {
            account: VId(9),
            account_row: account(),
            period: "FY2026-P01".into(),
            known_at: CommitSeq(7),
            fold_digest: [1; 32],
            watermark: None,
            cells: Vec::new(),
            pending: Vec::new(),
            contributions: Vec::new(),
            history: Vec::new(),
        }));
        let mut selection = ReportSelection::ExplainBalance {
            account: VId(9),
            period: "FY2026-P01".into(),
        };
        let mut entry = posting(EntryClass::ORIGINAL, 1);
        assert!(
            entry
                .proposal
                .legs
                .iter()
                .all(|leg| leg.account_ref != VId(9))
        );
        assert!(selected(&book, &selection, &report, &entry, &BTreeMap::new()).unwrap());
        entry.proposal.effective_date = DateDay::from_ymd(2026, 2, 15).unwrap();
        assert!(!selected(&book, &selection, &report, &entry, &BTreeMap::new()).unwrap());
        entry.proposal.class = EntryClass::ADJUSTING;
        entry.proposal.effective_date = DateDay::from_ymd(2026, 12, 31).unwrap();
        entry.proposal.effective_period = Some(fa_model::PeriodRef {
            calendar: "cy".into(),
            code: "FY2026-A1".into(),
        });
        selection = ReportSelection::ExplainBalance {
            account: VId(9),
            period: "FY2026-A1".into(),
        };
        if let ReportOutput::ExplainBalance(report) = &mut report {
            report.period = "FY2026-A1".into();
        }
        assert!(selected(&book, &selection, &report, &entry, &BTreeMap::new()).unwrap());
        entry.proposal.effective_period.as_mut().unwrap().code = "FY2026-P12".into();
        assert!(!selected(&book, &selection, &report, &entry, &BTreeMap::new()).unwrap());
    }

    #[test]
    fn functional_consolidation_v7_preserves_native_v6_and_binds_fx_sources() {
        let native = ReportSelection::Consolidation {
            period: "FY2026-P03".into(),
        };
        let functional = ReportSelection::FunctionalConsolidation {
            period: "FY2026-P03".into(),
        };
        for (selection, version, tag) in [(&native, 6, 4), (&functional, 7, 5)] {
            let mut writer = Writer::new();
            selection.write(&mut writer).unwrap();
            let bytes = writer.finish().unwrap();
            assert_eq!(bytes[0], tag);
            let mut reader = Reader::new(&bytes);
            assert_eq!(
                &ReportSelection::read(&mut reader, version).unwrap(),
                selection
            );
            reader.finish().unwrap();
            for other_version in (1..=7).filter(|candidate| *candidate != version) {
                assert!(ReportSelection::read(&mut Reader::new(&bytes), other_version).is_err());
            }
        }
        let native_inputs = statements(CommitSeq(7), &native);
        let functional_inputs = statements(CommitSeq(7), &functional);
        assert_eq!(functional_inputs[..INPUTS.len()], native_inputs);
        assert_eq!(functional_inputs.len(), INPUTS.len() + 1);
        assert!(
            functional_inputs
                .last()
                .unwrap()
                .contains("WHERE n.code = 'Rate'")
        );
        assert_eq!(
            report_registries(&native)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            [
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "account_roles",
                "rounding_laws"
            ]
        );
        assert_eq!(
            report_registries(&functional)
                .into_iter()
                .map(|(name, _)| name)
                .collect::<Vec<_>>(),
            [
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "account_roles",
                "fx_laws",
                "rounding_laws"
            ]
        );
        assert_ne!(
            registry_digest(&native).unwrap(),
            registry_digest(&functional).unwrap()
        );
        assert_eq!(
            wire_fixture(native, None).format(),
            CONSOLIDATION_CERTIFICATE_FORMAT
        );
        let certificate = wire_fixture(functional, None);
        assert_eq!(
            certificate.format(),
            FUNCTIONAL_CONSOLIDATION_CERTIFICATE_FORMAT
        );
        assert_eq!(
            certificate.output_format(),
            FUNCTIONAL_CONSOLIDATION_OUTPUT_FORMAT
        );
        assert_eq!(certificate.body_bytes().unwrap().last(), Some(&0));
    }

    #[test]
    fn dimension_trial_balance_v8_binds_its_dimension_values_and_reserves_its_tag() {
        let selection = ReportSelection::DimensionTrialBalance {
            selection: TrialBalanceSelection::Activity(vec!["FY2026-P03".into()]),
            dimension: "cost_center".into(),
            value: "CC10".into(),
        };
        let mut writer = Writer::new();
        selection.write(&mut writer).unwrap();
        let bytes = writer.finish().unwrap();
        assert_eq!(bytes[0], 6);
        let mut reader = Reader::new(&bytes);
        assert_eq!(ReportSelection::read(&mut reader, 8).unwrap(), selection);
        reader.finish().unwrap();
        // No earlier format reads the tag, and v8 reads no other selector.
        for version in 3..=7 {
            assert!(ReportSelection::read(&mut Reader::new(&bytes), version).is_err());
        }
        let mut consolidation = Writer::new();
        ReportSelection::Consolidation {
            period: "FY2026-P03".into(),
        }
        .write(&mut consolidation)
        .unwrap();
        assert!(
            ReportSelection::read(&mut Reader::new(&consolidation.finish().unwrap()), 8).is_err()
        );
        let certificate = wire_fixture(selection.clone(), None);
        assert_eq!(
            certificate.format(),
            DIMENSION_TRIAL_BALANCE_CERTIFICATE_FORMAT
        );
        assert_eq!(
            certificate.output_format(),
            DIMENSION_TRIAL_BALANCE_OUTPUT_FORMAT
        );
        assert_eq!(
            certificate.body_bytes().unwrap().last(),
            Some(&0),
            "no TimeEvidence selection"
        );
        // One more native input, holding only cost_center's values (id 2):
        // party and legal-entity values never enter the closure.
        let inputs = statements(CommitSeq(7), &selection);
        assert_eq!(inputs.len(), INPUTS.len() + 1);
        let bound = inputs.last().unwrap();
        assert!(
            bound.starts_with(
                "MATCH (n:DimensionValue) FOR SYSTEM_TIME AS OF SEQ 7 WHERE n.dimension_id = 2 "
            ),
            "{bound}"
        );
        let plain =
            ReportSelection::from(TrialBalanceSelection::Activity(vec!["FY2026-P03".into()]));
        assert_eq!(statements(CommitSeq(7), &plain).len(), INPUTS.len());
        // An unregistered dimension and an empty or oversized value are not
        // canonical selectors.
        let long = "C".repeat(fa_model::rea::MAX_REA_CODE_BYTES + 1);
        for (dimension, value) in [
            ("cost_centre", "CC10"),
            ("cost_center", ""),
            ("cost_center", long.as_str()),
        ] {
            assert!(
                !ReportSelection::DimensionTrialBalance {
                    selection: TrialBalanceSelection::AsOf(DateDay(1)),
                    dimension: dimension.into(),
                    value: value.into(),
                }
                .is_canonical(),
                "{dimension}={value}"
            );
        }
    }

    /// fa-doa9: a regulatory schedule is selector tag 7, read only by v9. The
    /// selector binds the complete schedule (form, schedule code,
    /// instruction version, code-mapped definition, declared inputs), so a
    /// changed instruction version is a different certificate question.
    #[test]
    fn regulatory_schedule_v9_binds_its_complete_schedule_and_reserves_its_tag() {
        use fa_statements::regulatory::RegulatoryScheduleDefinition;
        let normalized = crate::statements::RegulatorySelection {
            schedule: RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1(),
            periods: vec![
                "FY2026-P03".into(),
                "FY2026-P01".into(),
                "FY2026-P02".into(),
            ],
            comparative: vec![],
        }
        .normalize();
        let selection = ReportSelection::RegulatorySchedule(Box::new(normalized.clone()));
        assert_eq!(selection.clone().normalize(), selection);
        assert_eq!(
            normalized.periods,
            ["FY2026-P01", "FY2026-P02", "FY2026-P03"],
            "a year-to-date RI selects its periods in canonical order"
        );
        let mut writer = Writer::new();
        selection.write(&mut writer).unwrap();
        let bytes = writer.finish().unwrap();
        assert_eq!(bytes[0], 7);
        let mut reader = Reader::new(&bytes);
        assert_eq!(ReportSelection::read(&mut reader, 9).unwrap(), selection);
        reader.finish().unwrap();
        // No earlier format reads the tag, and v9 reads no other selector.
        for version in 3..=8 {
            assert!(ReportSelection::read(&mut Reader::new(&bytes), version).is_err());
        }
        let mut statement = Writer::new();
        ReportSelection::from(crate::StatementSelection {
            definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
            periods: vec!["FY2026-P03".into()],
            comparative: vec![],
        })
        .write(&mut statement)
        .unwrap();
        assert!(ReportSelection::read(&mut Reader::new(&statement.finish().unwrap()), 9).is_err());
        let certificate = wire_fixture(selection.clone(), None);
        assert_eq!(certificate.format(), REGULATORY_SCHEDULE_CERTIFICATE_FORMAT);
        assert_eq!(
            certificate.output_format(),
            REGULATORY_SCHEDULE_OUTPUT_FORMAT
        );
        // No bound input beyond the native closure every report carries.
        assert_eq!(statements(CommitSeq(7), &selection).len(), INPUTS.len());
        // The selector is the whole schedule: another instruction version
        // encodes differently.
        let mut revised = normalized.clone();
        revised.schedule.instruction_version = "FFIEC-041-2026Q2".into();
        let mut other = Writer::new();
        ReportSelection::RegulatorySchedule(Box::new(revised))
            .write(&mut other)
            .unwrap();
        assert_ne!(other.finish().unwrap(), bytes);
        // No period, and a schedule that does not validate, are not
        // canonical selectors.
        let mut empty = normalized.clone();
        empty.periods.clear();
        assert!(!ReportSelection::RegulatorySchedule(Box::new(empty)).is_canonical());
        let mut invalid = normalized.clone();
        invalid.schedule.schedule_code.clear();
        assert!(!ReportSelection::RegulatorySchedule(Box::new(invalid)).is_canonical());
    }

    #[test]
    fn custom_statement_v11_pins_approval_layout_and_presentation_without_reusing_tags() {
        let definition = fa_statements::custom::CustomStatementDefinition::from_builtin(
            &crate::StatementDefinition::embedded("income-statement").unwrap(),
        );
        let selection =
            ReportSelection::CustomStatement(Box::new(crate::CustomStatementSelection {
                definition,
                activation: VId(77),
                activated_at: CommitSeq(5),
                functional: false,
                periods: vec!["FY2026-P03".into()],
                comparative: vec!["FY2025-P03".into()],
                presentation: Some(fa_statements::custom::PresentationRoundingSpec {
                    rounding_law: fa_money::RoundingLaw::HalfEven,
                    scale_reduction_digits: 5,
                    residual_line_code: "rounding".into(),
                    residual_line_label: "Presentation rounding".into(),
                }),
            }));
        assert!(selection.is_canonical());
        let encode = |selection: &ReportSelection| {
            let mut writer = Writer::new();
            selection.write(&mut writer).unwrap();
            writer.finish().unwrap()
        };
        let bytes = encode(&selection);
        assert_eq!(bytes[0], 9);
        let mut reader = Reader::new(&bytes);
        assert_eq!(ReportSelection::read(&mut reader, 11).unwrap(), selection);
        reader.finish().unwrap();
        for version in 1..=10 {
            assert!(ReportSelection::read(&mut Reader::new(&bytes), version).is_err());
        }
        let certificate = wire_fixture(selection.clone(), None);
        assert_eq!(certificate.format(), CUSTOM_STATEMENT_CERTIFICATE_FORMAT);
        assert_eq!(
            certificate.output_format(),
            crate::custom_statement::OUTPUT_FORMAT
        );
        assert_eq!(certificate.body_bytes().unwrap().last(), Some(&0));
        let inputs = statements(CommitSeq(7), &selection);
        assert_eq!(inputs.len(), INPUTS.len() + CUSTOM_STATEMENT_INPUTS);
        for (offset, kind, sequence) in [
            (0, "StatementDefinition", 7),
            (1, "Approval", 5),
            (2, "Book", 5),
            (3, "Account", 4),
            (4, "Book", 4),
        ] {
            assert!(inputs[INPUTS.len() + offset].starts_with(&format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {sequence} "
            )));
            assert_eq!(
                input_snapshot(CommitSeq(7), &selection, INPUTS.len() + offset),
                CommitSeq(sequence)
            );
        }
        assert!(
            report_registries(&selection)
                .iter()
                .any(|(name, _)| *name == "rounding_laws")
        );
        for change in 0..5 {
            let mut modified = selection.clone();
            let ReportSelection::CustomStatement(layout) = &mut modified else {
                unreachable!()
            };
            match change {
                0 => layout.activation = VId(78),
                1 => layout.definition.lines[0].label.push_str(" revised"),
                2 => {
                    layout.presentation.as_mut().unwrap().rounding_law =
                        fa_money::RoundingLaw::Floor
                }
                3 => layout.activated_at = CommitSeq(6),
                _ => {
                    layout.presentation.as_mut().unwrap().residual_line_code =
                        "other_rounding".into()
                }
            }
            assert_ne!(
                encode(&modified),
                bytes,
                "every reviewed/output input is bound"
            );
        }
    }

    #[test]
    fn functional_custom_statement_v12_separates_basis_and_binds_original_rate_and_approval_sources()
     {
        let definition = fa_statements::custom::CustomStatementDefinition::from_builtin(
            &crate::StatementDefinition::embedded("income-statement").unwrap(),
        );
        let native = ReportSelection::CustomStatement(Box::new(crate::CustomStatementSelection {
            definition: definition.clone(),
            activation: VId(77),
            activated_at: CommitSeq(5),
            functional: false,
            periods: vec!["FY2026-P03".into()],
            comparative: vec!["FY2026-P02".into()],
            presentation: None,
        }));
        let mut functional = native.clone();
        let ReportSelection::CustomStatement(selected) = &mut functional else {
            unreachable!()
        };
        selected.functional = true;
        let encode = |selection: &ReportSelection| {
            let mut writer = Writer::new();
            selection.write(&mut writer).unwrap();
            writer.finish().unwrap()
        };
        let native_bytes = encode(&native);
        let functional_bytes = encode(&functional);
        assert_eq!(native_bytes[0], 9);
        assert_eq!(functional_bytes[0], 10);
        assert_eq!(
            native_bytes[1..],
            functional_bytes[1..],
            "the new basis tag does not insert a field into the v11 selector payload",
        );
        let mut reader = Reader::new(&functional_bytes);
        assert_eq!(ReportSelection::read(&mut reader, 12).unwrap(), functional);
        reader.finish().unwrap();
        for version in 1..=11 {
            assert!(ReportSelection::read(&mut Reader::new(&functional_bytes), version).is_err());
        }
        assert!(ReportSelection::read(&mut Reader::new(&native_bytes), 12).is_err());
        assert_eq!(
            ReportSelection::read(&mut Reader::new(&native_bytes), 11).unwrap(),
            native
        );
        assert!(!native.uses_functional_valuations());
        assert!(functional.uses_functional_valuations());

        let native_certificate = wire_fixture(native.clone(), None);
        let functional_certificate = wire_fixture(functional.clone(), None);
        assert_eq!(
            native_certificate.format(),
            CUSTOM_STATEMENT_CERTIFICATE_FORMAT
        );
        assert_eq!(
            functional_certificate.format(),
            FUNCTIONAL_CUSTOM_STATEMENT_CERTIFICATE_FORMAT
        );
        assert_eq!(
            native_certificate.output_format(),
            crate::custom_statement::OUTPUT_FORMAT
        );
        assert_eq!(
            functional_certificate.output_format(),
            crate::custom_statement::FUNCTIONAL_OUTPUT_FORMAT
        );
        assert_eq!(
            functional_certificate.body_bytes().unwrap().last(),
            Some(&0)
        );
        assert_ne!(
            native_certificate.body_bytes().unwrap(),
            functional_certificate.body_bytes().unwrap()
        );

        let inputs = statements(CommitSeq(7), &functional);
        assert_eq!(inputs.len(), 13);
        let rate = &inputs[INPUTS.len()];
        assert!(
            rate.starts_with(
                "MATCH (n:Document) FOR SYSTEM_TIME AS OF SEQ 7 WHERE n.code = 'Rate' "
            )
        );
        assert_eq!(
            input_snapshot(CommitSeq(7), &functional, INPUTS.len()),
            CommitSeq(7)
        );
        for (offset, kind, sequence) in [
            (0, "StatementDefinition", 7),
            (1, "Approval", 5),
            (2, "Book", 5),
            (3, "Account", 4),
            (4, "Book", 4),
        ] {
            let index = INPUTS.len() + 1 + offset;
            assert!(inputs[index].starts_with(&format!(
                "MATCH (n:{kind}) FOR SYSTEM_TIME AS OF SEQ {sequence} "
            )));
            assert_eq!(
                input_snapshot(CommitSeq(7), &functional, index),
                CommitSeq(sequence)
            );
        }
        assert_eq!(statements(CommitSeq(7), &native).len(), 12);
        assert_eq!(
            report_registries(&functional)
                .iter()
                .map(|(name, _)| *name)
                .collect::<Vec<_>>(),
            [
                "account_types",
                "entry_classes",
                "units",
                "foundations",
                "fx_laws",
                "rounding_laws"
            ],
            "functional valuation and presentation use one exact copy of each law registry",
        );
        assert_ne!(
            registry_digest(&native).unwrap(),
            registry_digest(&functional).unwrap()
        );

        // Even when all amounts are zero, the report must identify which basis
        // was asked. Functional evidence cannot be presented as a native report.
        let statement = fa_statements::custom::evaluate_custom(
            &definition,
            &fa_statements::StatementInput {
                book_id: Id128([1; 16]),
                branch_id: Id128::TRUNK,
                known_at: 7,
                accounts: Vec::new(),
                units: vec![1],
                columns: vec![fa_statements::ColumnInput {
                    label: "current".into(),
                    periods: vec!["FY2026-P03".into()],
                    effective_from: Some(DateDay(0)),
                    effective_through: DateDay(30),
                    balances: Vec::new(),
                }],
            },
        )
        .unwrap();
        let native_output = crate::CustomStatementReport {
            activation: VId(77),
            functional_unit: None,
            statement,
            presented: None,
        };
        let mut functional_output = native_output.clone();
        functional_output.functional_unit = Some(fa_money::UnitId(1));
        let bytes = functional_output.canonical_bytes().unwrap();
        assert_ne!(native_output.canonical_bytes().unwrap(), bytes);
        let mut reader = Reader::new(&bytes);
        assert_eq!(
            reader
                .fixed::<{ crate::custom_statement::FUNCTIONAL_OUTPUT_FORMAT.len() }>("format")
                .unwrap(),
            crate::custom_statement::FUNCTIONAL_OUTPUT_FORMAT.as_bytes()
        );
        assert_eq!(reader.str(64, "basis").unwrap(), "retained-base-amounts");
        assert_eq!(reader.u32("functional unit").unwrap(), 1);
        assert_eq!(reader.u128("approved activation").unwrap(), 77);
        assert_eq!(
            reader
                .bytes(MAX_CERTIFICATE_BYTES, "exact statement")
                .unwrap(),
            native_output.statement.canonical_bytes().unwrap()
        );
        assert_eq!(reader.u8("presentation").unwrap(), 0);
        reader.finish().unwrap();
    }

    #[test]
    fn consolidation_status_selects_ownership_at_the_period_end_within_the_group() {
        let through = DateDay::from_ymd(2026, 1, 31).unwrap();
        let members = BTreeMap::from([
            (Id128(1u128.to_be_bytes()), "PARENT".to_string()),
            (Id128(2u128.to_be_bytes()), "SUB".to_string()),
        ]);
        let original = fa_model::RelationshipSpec {
            from: VId(1),
            to: VId(2),
            kind: fa_model::RelationshipKind::Owns {
                pct: fa_model::OwnershipPct::new(4, 5).unwrap(),
            },
            basis: "direct_equity_ownership".into(),
            valid_from: DateDay::from_ymd(2026, 1, 1).unwrap(),
            valid_to: None,
        };
        let selected = |relationship: &fa_model::RelationshipSpec| {
            consolidation_control_selected(
                through,
                &members,
                Some(&ControlPayload::SchemaChange {
                    kind: fa_model::rea::SCHEMA_CHANGE_RECORD_RELATIONSHIP,
                    canonical_bytes: relationship.encode().unwrap(),
                }),
            )
            .unwrap()
        };
        assert!(selected(&original));
        let mut changed = original.clone();
        changed.valid_from = through;
        assert!(selected(&changed));
        changed.valid_from = DateDay::from_ymd(2026, 2, 1).unwrap();
        assert!(
            !selected(&changed),
            "future ownership leaves January current"
        );
        let mut changed = original.clone();
        changed.valid_to = Some(through);
        assert!(!selected(&changed), "the ownership end is exclusive");
        changed.valid_to = Some(DateDay::from_ymd(2026, 2, 1).unwrap());
        assert!(selected(&changed));
        for (from, to) in [(VId(1), VId(99)), (VId(99), VId(2))] {
            let mut changed = original.clone();
            changed.from = from;
            changed.to = to;
            assert!(!selected(&changed), "both endpoints must be group members");
        }
        for kind in [
            fa_model::RelationshipKind::Controls,
            fa_model::RelationshipKind::RelatedTo,
        ] {
            let mut changed = original.clone();
            changed.kind = kind;
            assert!(!selected(&changed));
        }
        let mut malformed = original.encode().unwrap();
        malformed.push(0);
        assert!(
            consolidation_control_selected(
                through,
                &members,
                Some(&ControlPayload::SchemaChange {
                    kind: fa_model::rea::SCHEMA_CHANGE_RECORD_RELATIONSHIP,
                    canonical_bytes: malformed,
                }),
            )
            .is_err(),
            "an undecodable relationship must not become an unrelated control"
        );
    }

    #[test]
    fn consolidation_status_selects_its_role_assignments_and_removals() {
        let through = DateDay::from_ymd(2026, 1, 31).unwrap();
        let members = BTreeMap::new();
        for assigned in [true, false] {
            for (role, relevant) in [
                ("contributed_capital", true),
                ("intercompany", true),
                ("intercompany_activity", true),
                ("investment_in_subsidiary", true),
                ("noncontrolling_interest", true),
                ("noncontrolling_interest_income", true),
                ("cash", false),
                ("receivable", false),
            ] {
                let control = ControlPayload::SchemaChange {
                    kind: fa_journal::account_role::SCHEMA_CHANGE_ACCOUNT_ROLE,
                    canonical_bytes: fa_journal::account_role::AccountRoleSpec {
                        account: VId(9),
                        role: role.into(),
                        assigned,
                    }
                    .encode()
                    .unwrap(),
                };
                assert_eq!(
                    consolidation_control_selected(through, &members, Some(&control)).unwrap(),
                    relevant,
                    "role {role}, assigned {assigned}"
                );
            }
        }
        assert!(
            consolidation_control_selected(
                through,
                &members,
                Some(&ControlPayload::SchemaChange {
                    kind: fa_journal::account_role::SCHEMA_CHANGE_ACCOUNT_ROLE,
                    canonical_bytes: Vec::new(),
                }),
            )
            .is_err()
        );
    }

    #[test]
    fn open_item_status_follows_reversal_lineage_and_excludes_non_item_classes() {
        for (class, contributes) in [
            (EntryClass::ORIGINAL, true),
            (EntryClass::ADJUSTING, true),
            (EntryClass::CLOSING, true),
            (EntryClass::PENDING, false),
        ] {
            let original = posting(class, 1);
            let first = reversal(&original, VId(10), 2);
            let second = reversal(&first, VId(11), 3);
            let entries = BTreeMap::from([(VId(10), original), (VId(11), first)]);
            assert_eq!(
                open_item_selected(&second, &entries, None).unwrap(),
                contributes
            );
            assert_eq!(
                open_item_selected(&second, &entries, Some(VId(1))).unwrap(),
                contributes
            );
            assert!(!open_item_selected(&second, &entries, Some(VId(99))).unwrap());
        }
        let original = posting(EntryClass::ORIGINAL, 1);
        let mut first = reversal(&original, VId(10), 2);
        first.proposal.supersession[0].target.vid = VId(11);
        let entries = BTreeMap::from([(VId(11), first.clone())]);
        assert!(open_item_selected(&first, &entries, None).is_err());
    }

    #[test]
    fn current_report_comparison_normalizes_only_the_outer_query_coordinate() {
        let explanation = BalanceExplanation {
            account: VId(9),
            account_row: account(),
            period: "FY2026-P01".into(),
            known_at: CommitSeq(7),
            fold_digest: [4; 32],
            watermark: Some(CommitSeq(5)),
            cells: Vec::new(),
            pending: Vec::new(),
            contributions: Vec::new(),
            history: vec![fa_registers::explain::CellChange {
                recorded_at: CommitSeq(5),
                unit_id: 0,
                debits: 100,
                credits: 0,
                debits_pending: 0,
                credits_pending: 0,
            }],
        };
        let original = ReportOutput::ExplainBalance(Box::new(explanation));
        let expected = original.canonical_bytes().unwrap();
        let mut later = original.clone();
        if let ReportOutput::ExplainBalance(report) = &mut later {
            report.known_at = CommitSeq(12);
        }
        later.normalize_known_at(original.known_at());
        assert_eq!(later.canonical_bytes().unwrap(), expected);
        if let ReportOutput::ExplainBalance(report) = &mut later {
            report.watermark = Some(CommitSeq(6));
            report.history[0].recorded_at = CommitSeq(6);
        }
        later.normalize_known_at(original.known_at());
        assert_ne!(later.canonical_bytes().unwrap(), expected);

        let item = fa_registers::open_items::OpenItem {
            entry: VId(10),
            ordinal: 0,
            account: VId(9),
            unit_id: 0,
            side: Side::Debit,
            effective_date: DateDay(20_000),
            recorded_at: CommitSeq(4),
            original: 100,
            applied: 0,
            applied_out: 0,
            open: 100,
            applications: Vec::new(),
        };
        let original = ReportOutput::OpenItems(OpenItemsReport {
            known_at: CommitSeq(7),
            account_filter: Some(VId(9)),
            accounts: BTreeMap::from([(VId(9), account())]),
            items: vec![item],
        });
        let expected = original.canonical_bytes().unwrap();
        let mut later = original.clone();
        if let ReportOutput::OpenItems(report) = &mut later {
            report.known_at = CommitSeq(12);
        }
        later.normalize_known_at(original.known_at());
        assert_eq!(later.canonical_bytes().unwrap(), expected);
        if let ReportOutput::OpenItems(report) = &mut later {
            report.items[0].recorded_at = CommitSeq(5);
        }
        later.normalize_known_at(original.known_at());
        assert_ne!(later.canonical_bytes().unwrap(), expected);
    }

    #[test]
    fn metadata_status_compares_only_the_fields_the_report_emits() {
        let row = account();
        let trial = AccountMetadata::TrialBalance {
            code: row.code.clone(),
            name: row.name.clone(),
            account_type: row.account_type,
        };
        let complete = AccountMetadata::Complete(row.clone());
        let mut later = row;
        later.limit = Some(BalanceLimit {
            lower: None,
            upper: Some(1_000),
            scope: LimitScope::Period,
        });
        assert_eq!(trial.project(later.clone()), trial);
        assert_ne!(complete.project(later.clone()), complete);
        later.name = "Renamed receivables".into();
        assert_ne!(trial.project(later.clone()), trial);
        assert_ne!(complete.project(later), complete);
    }
}
