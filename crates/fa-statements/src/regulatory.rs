//! Regulatory schedule definitions (FFIEC 031/041 Call Report Schedules RC/RI
//! and FR Y-9C Schedules HC/HI) with recorded instruction versions, declared
//! `Instrument` graph attribute inputs, and the versioned FFIEC validity and
//! quality edits registry (`regulatory.edits(<form>@<quarter>)`) (plan §12.6,
//! bead `fa-pbm`).
//!
//! No floating-point type enters any calculation. Every schedule evaluation and
//! regulatory edit check is certified with canonical bytes and a domain-separated
//! BLAKE3 digest (`fa-cqk`).

use std::collections::{BTreeMap, BTreeSet};

use fa_model::{EncodeError, Oid, Reader, Writer, domain_digest};

use crate::{
    Sign, Statement, StatementError, StatementInput, StatementKind,
    custom::{
        AccountSetExpr, CustomLineDefinition, CustomLineSource, CustomStatementDefinition,
        evaluate_custom,
    },
};

pub const REGULATORY_SCHEDULE_DEF_FORMAT: &[u8] = b"fa:regulatory-schedule-def:v1";
pub const REGULATORY_EDIT_REPORT_FORMAT: &[u8] = b"fa:regulatory-edit-report:v1";

const MAX_DECLARED_INPUTS: usize = 64;
const MAX_EDIT_TERMS: usize = 32;
const MAX_EDIT_CHECK_ROWS: usize = 4096;

/// Regulatory filing form family (plan §12.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegulatoryForm {
    /// FFIEC 031 Consolidated Reports of Condition and Income for a Bank with Domestic and Foreign Offices.
    Ffiec031,
    /// FFIEC 041 Consolidated Reports of Condition and Income for a Bank with Domestic Offices Only.
    Ffiec041,
    /// Federal Reserve FR Y-9C Consolidated Financial Statements for Holding Companies.
    FrY9C,
}

impl RegulatoryForm {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ffiec031 => "FFIEC031",
            Self::Ffiec041 => "FFIEC041",
            Self::FrY9C => "FRY9C",
        }
    }

    pub const fn tag(self) -> u8 {
        match self {
            Self::Ffiec031 => 0,
            Self::Ffiec041 => 1,
            Self::FrY9C => 2,
        }
    }

    fn from_tag(tag: u8, r: &Reader<'_>) -> Result<Self, fa_model::DecodeError> {
        match tag {
            0 => Ok(Self::Ffiec031),
            1 => Ok(Self::Ffiec041),
            2 => Ok(Self::FrY9C),
            other => Err(r.bad_tag("regulatory_form", other)),
        }
    }
}

/// Declaration of an `Instrument` graph attribute required by a schedule line
/// that the general ledger alone does not hold (e.g., RC-E deposit insurance
/// capacity, RC-N past-due days, RC-R risk weight) (plan §12.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstrumentAttributeInputSpec {
    pub line_code: String,
    pub instrument_kind: String,
    pub attribute_name: String,
}

/// Regulatory schedule definition wrapping a [`CustomStatementDefinition`] with
/// its filing form, schedule code, regulatory instructions version, and declared
/// `Instrument`-graph inputs (plan §12.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatoryScheduleDefinition {
    pub form: RegulatoryForm,
    pub schedule_code: String,
    pub instruction_version: String,
    pub statement_definition: CustomStatementDefinition,
    pub declared_instrument_inputs: Vec<InstrumentAttributeInputSpec>,
}

impl RegulatoryScheduleDefinition {
    pub fn validate(&self) -> Result<(), StatementError> {
        if self.schedule_code.trim().is_empty() || self.schedule_code.len() > 32 {
            return Err(StatementError::Definition(
                "regulatory schedule_code must be non-empty and at most 32 bytes".into(),
            ));
        }
        if self.instruction_version.trim().is_empty() || self.instruction_version.len() > 64 {
            return Err(StatementError::Definition(
                "regulatory instruction_version must be non-empty and at most 64 bytes".into(),
            ));
        }
        if self.declared_instrument_inputs.len() > MAX_DECLARED_INPUTS {
            return Err(StatementError::Definition(
                "declared_instrument_inputs exceeds maximum of 64".into(),
            ));
        }
        self.statement_definition.validate()?;
        let line_codes: BTreeSet<&str> = self
            .statement_definition
            .lines
            .iter()
            .map(|l| l.code.as_str())
            .collect();
        for input_spec in &self.declared_instrument_inputs {
            if !line_codes.contains(input_spec.line_code.as_str()) {
                return Err(StatementError::Definition(format!(
                    "declared instrument input references unknown schedule line `{}`",
                    input_spec.line_code
                )));
            }
            if input_spec.instrument_kind.trim().is_empty()
                || input_spec.instrument_kind.len() > 64
                || input_spec.attribute_name.trim().is_empty()
                || input_spec.attribute_name.len() > 64
            {
                return Err(StatementError::Definition(
                    "instrument_kind and attribute_name must be non-empty and at most 64 bytes"
                        .into(),
                ));
            }
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Result<Vec<u8>, StatementError> {
        self.validate()?;
        let def_bytes = self.statement_definition.canonical_bytes()?;
        let mut w = Writer::new();
        w.fixed(REGULATORY_SCHEDULE_DEF_FORMAT)
            .u8(self.form.tag())
            .str(&self.schedule_code)
            .str(&self.instruction_version)
            .bytes(&def_bytes)
            .list(&self.declared_instrument_inputs, |w, spec| {
                w.str(&spec.line_code)
                    .str(&spec.instrument_kind)
                    .str(&spec.attribute_name);
            });
        Ok(w.finish()?)
    }

    pub fn digest(&self) -> Result<Oid, StatementError> {
        Ok(Oid(domain_digest(
            REGULATORY_SCHEDULE_DEF_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, StatementError> {
        let mut r = Reader::new(bytes);
        let magic = r.fixed::<{ REGULATORY_SCHEDULE_DEF_FORMAT.len() }>("reg_sched.magic")?;
        if magic != REGULATORY_SCHEDULE_DEF_FORMAT {
            return Err(StatementError::Definition(
                "unknown regulatory schedule definition header".into(),
            ));
        }
        let form_tag = r.u8("form")?;
        let form = RegulatoryForm::from_tag(form_tag, &r)?;
        let schedule_code = r.str(32, "schedule_code")?.to_string();
        let instruction_version = r.str(64, "instruction_version")?.to_string();
        let def_bytes = r.bytes(65_536, "statement_definition")?;
        let statement_definition = CustomStatementDefinition::decode(def_bytes)?;
        let declared_instrument_inputs =
            r.list(MAX_DECLARED_INPUTS, "declared_instrument_inputs", |r| {
                let line_code = r.str(64, "line_code")?.to_string();
                let instrument_kind = r.str(64, "instrument_kind")?.to_string();
                let attribute_name = r.str(64, "attribute_name")?.to_string();
                Ok(InstrumentAttributeInputSpec {
                    line_code,
                    instrument_kind,
                    attribute_name,
                })
            })?;
        r.finish()?;
        let schedule = Self {
            form,
            schedule_code,
            instruction_version,
            statement_definition,
            declared_instrument_inputs,
        };
        schedule.validate()?;
        Ok(schedule)
    }

    /// Evaluate this regulatory schedule against a [`StatementInput`].
    pub fn evaluate(&self, input: &StatementInput) -> Result<Statement, StatementError> {
        self.validate()?;
        evaluate_custom(&self.statement_definition, input)
    }

    /// FFIEC 041 Schedule RC — Consolidated Report of Condition (Balance Sheet),
    /// instruction version `FFIEC-041-2026Q1`.
    ///
    /// Bank chart convention:
    /// - `10..` Noninterest-bearing cash and due from depository institutions (`RCON0081`)
    /// - `11..` Interest-bearing balances (`RCON0071`)
    /// - `12..` Held-to-maturity securities (`RCONJJ34`)
    /// - `13..` Available-for-sale debt securities (`RCON1773`)
    /// - `14..` Loans and leases held for investment (`RCON2122`)
    /// - `15..` Less: Allowance for credit losses on loans and leases (`RCON3123`, credit normal)
    /// - Net loans and leases (`RCONB529 = RCON2122 - RCON3123`)
    /// - `16..`–`19..` Premises, fixed assets, and other assets (`RCON2145`)
    /// - Total assets (`RCON2170 = RCON0081 + RCON0071 + RCONJJ34 + RCON1773 + RCONB529 + RCON2145`)
    /// - `20..`–`22..` Total deposits in domestic offices (`RCON2200`)
    /// - `23..`–`25..` Other borrowed money (`RCON3190`)
    /// - `26..`–`29..` Other liabilities (`RCON2930`)
    /// - Total liabilities (`RCON2948 = RCON2200 + RCON3190 + RCON2930`)
    /// - `30..` Common stock (`RCON3230`)
    /// - `31..` Surplus (`RCON3839`)
    /// - All other Equity (`RCON3632` Retained earnings and other equity capital)
    /// - Total bank equity capital (`RCON3210 = RCON3230 + RCON3839 + RCON3632`)
    /// - Total liabilities and equity capital (`RCON3300 = RCON2948 + RCON3210`)
    #[must_use]
    pub fn ffiec_041_schedule_rc_2026q1() -> Self {
        let statement_definition = CustomStatementDefinition {
            name: "ffiec_041_schedule_rc_2026q1".into(),
            title: "FFIEC 041 Schedule RC - Consolidated Report of Condition (2026Q1)".into(),
            version: 1,
            kind: StatementKind::BalanceSheet,
            lines: vec![
                CustomLineDefinition {
                    code: "RCON0081".into(),
                    label: "Cash and noninterest-bearing balances due from depository institutions"
                        .into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["10".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON0071".into(),
                    label: "Interest-bearing balances due from depository institutions".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["11".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCONJJ34".into(),
                    label: "Held-to-maturity securities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["12".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON1773".into(),
                    label: "Available-for-sale debt securities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["13".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON2122".into(),
                    label: "Loans and leases held for investment".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["14".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON3123".into(),
                    label: "Allowance for credit losses on loans and leases".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["15".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCONB529".into(),
                    label: "Loans and leases held for investment, net of allowance".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RCON2122".into()],
                        subtract: vec!["RCON3123".into()],
                    },
                },
                CustomLineDefinition {
                    code: "RCON2145".into(),
                    label: "Premises and fixed assets and other assets".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![1])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "10".into(),
                                "11".into(),
                                "12".into(),
                                "13".into(),
                                "14".into(),
                                "15".into(),
                            ])),
                        },
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON2170".into(),
                    label: "Total assets".into(),
                    source: CustomLineSource::Formula {
                        add: vec![
                            "RCON0071".into(),
                            "RCON0081".into(),
                            "RCON1773".into(),
                            "RCON2145".into(),
                            "RCONB529".into(),
                            "RCONJJ34".into(),
                        ],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "RCON2200".into(),
                    label: "Deposits in domestic offices".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec![
                            "20".into(),
                            "21".into(),
                            "22".into(),
                        ]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON3190".into(),
                    label: "Other borrowed money".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec![
                            "23".into(),
                            "24".into(),
                            "25".into(),
                        ]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON2930".into(),
                    label: "Other liabilities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![2])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "20".into(),
                                "21".into(),
                                "22".into(),
                                "23".into(),
                                "24".into(),
                                "25".into(),
                            ])),
                        },
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON2948".into(),
                    label: "Total liabilities".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RCON2200".into(), "RCON2930".into(), "RCON3190".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "RCON3230".into(),
                    label: "Common stock".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["30".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON3839".into(),
                    label: "Surplus".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["31".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON3632".into(),
                    label: "Retained earnings and undivided profits".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![3, 4, 5])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "30".into(),
                                "31".into(),
                            ])),
                        },
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RCON3210".into(),
                    label: "Total bank equity capital".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RCON3230".into(), "RCON3632".into(), "RCON3839".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "RCON3300".into(),
                    label: "Total liabilities and equity capital".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RCON2948".into(), "RCON3210".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "rc_balance_check".into(),
                    label: "Schedule RC balance check (RCON2170 - RCON3300)".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RCON2170".into()],
                        subtract: vec!["RCON3300".into()],
                    },
                },
            ],
            check_lines: vec!["rc_balance_check".into()],
        };

        Self {
            form: RegulatoryForm::Ffiec041,
            schedule_code: "RC".into(),
            instruction_version: "FFIEC-041-2026Q1".into(),
            statement_definition,
            declared_instrument_inputs: vec![
                InstrumentAttributeInputSpec {
                    line_code: "RCON2122".into(),
                    instrument_kind: "Loan".into(),
                    attribute_name: "call_report_loan_category".into(),
                },
                InstrumentAttributeInputSpec {
                    line_code: "RCON2200".into(),
                    instrument_kind: "Deposit".into(),
                    attribute_name: "fdic_part370_orc_code".into(),
                },
            ],
        }
    }

    /// FFIEC 041 Schedule RI — Consolidated Report of Income,
    /// instruction version `FFIEC-041-2026Q1`.
    #[must_use]
    pub fn ffiec_041_schedule_ri_2026q1() -> Self {
        let statement_definition = CustomStatementDefinition {
            name: "ffiec_041_schedule_ri_2026q1".into(),
            title: "FFIEC 041 Schedule RI - Consolidated Report of Income (2026Q1)".into(),
            version: 1,
            kind: StatementKind::IncomeStatement,
            lines: vec![
                CustomLineDefinition {
                    code: "RIAD4010".into(),
                    label: "Interest and fee income on loans".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["40".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4065".into(),
                    label: "Interest and dividend income on securities".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["41".into()]),
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4107".into(),
                    label: "Total interest income".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RIAD4010".into(), "RIAD4065".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4170".into(),
                    label: "Interest on deposits".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["50".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4185".into(),
                    label: "Interest on other borrowed money".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["51".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4073".into(),
                    label: "Total interest expense".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RIAD4170".into(), "RIAD4185".into()],
                        subtract: vec![],
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4074".into(),
                    label: "Net interest income".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RIAD4107".into()],
                        subtract: vec!["RIAD4073".into()],
                    },
                },
                CustomLineDefinition {
                    code: "RIADJJ33".into(),
                    label: "Provision for credit losses".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["52".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4079".into(),
                    label: "Total noninterest income".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![4])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "40".into(),
                                "41".into(),
                            ])),
                        },
                        sign: Sign::Credit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4093".into(),
                    label: "Total noninterest expense".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::Difference {
                            include: Box::new(AccountSetExpr::AccountTypes(vec![5])),
                            exclude: Box::new(AccountSetExpr::AccountCodePrefixes(vec![
                                "50".into(),
                                "51".into(),
                                "52".into(),
                                "80".into(),
                            ])),
                        },
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4301".into(),
                    label: "Income before applicable income taxes".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RIAD4074".into(), "RIAD4079".into()],
                        subtract: vec!["RIAD4093".into(), "RIADJJ33".into()],
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4302".into(),
                    label: "Applicable income taxes".into(),
                    source: CustomLineSource::AccountSet {
                        expr: AccountSetExpr::AccountCodePrefixes(vec!["80".into()]),
                        sign: Sign::Debit,
                    },
                },
                CustomLineDefinition {
                    code: "RIAD4340".into(),
                    label: "Net income (loss)".into(),
                    source: CustomLineSource::Formula {
                        add: vec!["RIAD4301".into()],
                        subtract: vec!["RIAD4302".into()],
                    },
                },
            ],
            check_lines: vec![],
        };

        Self {
            form: RegulatoryForm::Ffiec041,
            schedule_code: "RI".into(),
            instruction_version: "FFIEC-041-2026Q1".into(),
            statement_definition,
            declared_instrument_inputs: vec![],
        }
    }

    /// Federal Reserve FR Y-9C Schedule HC — Consolidated Balance Sheet for Holding Companies,
    /// instruction version `FR-Y-9C-2026Q1`.
    #[must_use]
    pub fn fr_y9c_schedule_hc_2026q1() -> Self {
        let mut rc = Self::ffiec_041_schedule_rc_2026q1();
        rc.form = RegulatoryForm::FrY9C;
        rc.schedule_code = "HC".into();
        rc.instruction_version = "FR-Y-9C-2026Q1".into();
        rc.statement_definition.name = "fr_y9c_schedule_hc_2026q1".into();
        rc.statement_definition.title =
            "FR Y-9C Schedule HC - Consolidated Balance Sheet (2026Q1)".into();
        for line in &mut rc.statement_definition.lines {
            line.code = line.code.replace("RCON", "BHCK");
            if let CustomLineSource::Formula { add, subtract } = &mut line.source {
                for op in add.iter_mut() {
                    *op = op.replace("RCON", "BHCK");
                }
                for op in subtract.iter_mut() {
                    *op = op.replace("RCON", "BHCK");
                }
                add.sort();
                subtract.sort();
            }
        }
        for spec in &mut rc.declared_instrument_inputs {
            spec.line_code = spec.line_code.replace("RCON", "BHCK");
        }
        rc
    }
}

/// FFIEC edit classification: hard `Validity` edit vs analytical `Quality` edit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum FfiecEditKind {
    /// Validity edit: mathematical or structural identity that must hold exactly.
    Validity,
    /// Quality edit: reasonableness/analytical check requiring review if violated.
    Quality,
}

impl FfiecEditKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Validity => "validity",
            Self::Quality => "quality",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Validity => 0,
            Self::Quality => 1,
        }
    }
}

/// Relational operator for an [`FfiecEditRule`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FfiecEditOperator {
    /// `LHS == RHS`
    Equals,
    /// `LHS >= RHS`
    GreaterOrEqual,
    /// `LHS <= RHS`
    LessOrEqual,
}

impl FfiecEditOperator {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Equals => "==",
            Self::GreaterOrEqual => ">=",
            Self::LessOrEqual => "<=",
        }
    }

    const fn tag(self) -> u8 {
        match self {
            Self::Equals => 0,
            Self::GreaterOrEqual => 1,
            Self::LessOrEqual => 2,
        }
    }
}

/// Signed linear term in an [`FfiecEditRule`] (`weight ∈ {-1, 1}`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiecEditTerm {
    pub line_code: String,
    pub weight: i8,
}

/// Versioned FFIEC / FR Y-9C validity or quality edit rule (plan §12.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FfiecEditRule {
    pub edit_id: String,
    pub form_at_quarter: String,
    pub schedule_code: String,
    pub kind: FfiecEditKind,
    pub description: String,
    pub lhs_terms: Vec<FfiecEditTerm>,
    pub operator: FfiecEditOperator,
    pub rhs_terms: Vec<FfiecEditTerm>,
}

/// Lookup FFIEC / FR Y-9C validity and quality edits for `<form>@<quarter>`
/// (plan §12.6 `regulatory.edits(<form>@<quarter>)`).
///
/// Supported selectors include `"FFIEC041@2026Q1"`, `"FFIEC041:RC@2026Q1"`,
/// `"FFIEC041:RI@2026Q1"`, and `"FRY9C@2026Q1"`.
pub fn regulatory_edits(form_at_quarter: &str) -> Result<Vec<FfiecEditRule>, StatementError> {
    let rc_edits = vec![
        FfiecEditRule {
            edit_id: "FFIEC041-RC-V001".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RC".into(),
            kind: FfiecEditKind::Validity,
            description: "Net loans and leases (RCONB529) must equal loans and leases held for investment (RCON2122) minus allowance for credit losses (RCON3123)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RCONB529".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![
                FfiecEditTerm {
                    line_code: "RCON2122".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "RCON3123".into(),
                    weight: -1,
                },
            ],
        },
        FfiecEditRule {
            edit_id: "FFIEC041-RC-V002".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RC".into(),
            kind: FfiecEditKind::Validity,
            description: "Total assets (RCON2170) must equal Total liabilities and equity capital (RCON3300)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RCON2170".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![FfiecEditTerm {
                line_code: "RCON3300".into(),
                weight: 1,
            }],
        },
        FfiecEditRule {
            edit_id: "FFIEC041-RC-V003".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RC".into(),
            kind: FfiecEditKind::Validity,
            description: "Total liabilities (RCON2948) must equal the sum of deposits (RCON2200), other borrowed money (RCON3190), and other liabilities (RCON2930)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RCON2948".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![
                FfiecEditTerm {
                    line_code: "RCON2200".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "RCON3190".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "RCON2930".into(),
                    weight: 1,
                },
            ],
        },
        FfiecEditRule {
            edit_id: "FFIEC041-RC-Q001".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RC".into(),
            kind: FfiecEditKind::Quality,
            description: "Loans and leases held for investment (RCON2122) should be greater than or equal to allowance for credit losses (RCON3123)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RCON2122".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::GreaterOrEqual,
            rhs_terms: vec![FfiecEditTerm {
                line_code: "RCON3123".into(),
                weight: 1,
            }],
        },
    ];

    let ri_edits = vec![
        FfiecEditRule {
            edit_id: "FFIEC041-RI-V001".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RI".into(),
            kind: FfiecEditKind::Validity,
            description: "Net interest income (RIAD4074) must equal Total interest income (RIAD4107) minus Total interest expense (RIAD4073)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RIAD4074".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![
                FfiecEditTerm {
                    line_code: "RIAD4107".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "RIAD4073".into(),
                    weight: -1,
                },
            ],
        },
        FfiecEditRule {
            edit_id: "FFIEC041-RI-V002".into(),
            form_at_quarter: "FFIEC041@2026Q1".into(),
            schedule_code: "RI".into(),
            kind: FfiecEditKind::Validity,
            description: "Net income (RIAD4340) must equal Income before taxes (RIAD4301) minus Applicable income taxes (RIAD4302)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "RIAD4340".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![
                FfiecEditTerm {
                    line_code: "RIAD4301".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "RIAD4302".into(),
                    weight: -1,
                },
            ],
        },
    ];

    let hc_edits = vec![
        FfiecEditRule {
            edit_id: "FRY9C-HC-V001".into(),
            form_at_quarter: "FRY9C@2026Q1".into(),
            schedule_code: "HC".into(),
            kind: FfiecEditKind::Validity,
            description: "Consolidated total assets (BHCK2170) must equal Total liabilities and equity capital (BHCK3300)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "BHCK2170".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![FfiecEditTerm {
                line_code: "BHCK3300".into(),
                weight: 1,
            }],
        },
        FfiecEditRule {
            edit_id: "FRY9C-HC-V002".into(),
            form_at_quarter: "FRY9C@2026Q1".into(),
            schedule_code: "HC".into(),
            kind: FfiecEditKind::Validity,
            description: "Net loans and leases (BHCKB529) must equal loans and leases (BHCK2122) minus allowance (BHCK3123)".into(),
            lhs_terms: vec![FfiecEditTerm {
                line_code: "BHCKB529".into(),
                weight: 1,
            }],
            operator: FfiecEditOperator::Equals,
            rhs_terms: vec![
                FfiecEditTerm {
                    line_code: "BHCK2122".into(),
                    weight: 1,
                },
                FfiecEditTerm {
                    line_code: "BHCK3123".into(),
                    weight: -1,
                },
            ],
        },
    ];

    match form_at_quarter {
        "FFIEC041:RC@2026Q1" => Ok(rc_edits),
        "FFIEC041:RI@2026Q1" => Ok(ri_edits),
        "FFIEC041@2026Q1" => {
            let mut all = rc_edits;
            all.extend(ri_edits);
            Ok(all)
        }
        "FRY9C:HC@2026Q1" | "FRY9C@2026Q1" => Ok(hc_edits),
        other => Err(StatementError::Input(format!(
            "unknown regulatory edit selector `{other}`; expected FFIEC041@2026Q1, FFIEC041:RC@2026Q1, FFIEC041:RI@2026Q1, or FRY9C@2026Q1"
        ))),
    }
}

/// Single evaluated FFIEC / FR Y-9C edit check row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatoryEditCheckRow {
    pub edit_id: String,
    pub kind: FfiecEditKind,
    pub column_label: String,
    pub unit_id: u32,
    pub lhs_mantissa: i128,
    pub operator: FfiecEditOperator,
    pub rhs_mantissa: i128,
    pub delta_mantissa: i128,
    pub passed: bool,
}

/// Certified report produced by [`evaluate_regulatory_edits`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegulatoryEditReport {
    pub form_at_quarter: String,
    pub schedule_digest: Oid,
    pub validity_passed: usize,
    pub validity_failed: usize,
    pub quality_passed: usize,
    pub quality_failed: usize,
    pub rows: Vec<RegulatoryEditCheckRow>,
}

impl RegulatoryEditReport {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, EncodeError> {
        let mut w = Writer::new();
        w.fixed(REGULATORY_EDIT_REPORT_FORMAT)
            .str(&self.form_at_quarter)
            .fixed(&self.schedule_digest.0)
            .u32(self.validity_passed as u32)
            .u32(self.validity_failed as u32)
            .u32(self.quality_passed as u32)
            .u32(self.quality_failed as u32)
            .list(&self.rows, |w, row| {
                w.str(&row.edit_id)
                    .u8(row.kind.tag())
                    .str(&row.column_label)
                    .u32(row.unit_id)
                    .i128(row.lhs_mantissa)
                    .u8(row.operator.tag())
                    .i128(row.rhs_mantissa)
                    .i128(row.delta_mantissa)
                    .bool(row.passed);
            });
        w.finish()
    }

    pub fn certificate_digest(&self) -> Result<Oid, EncodeError> {
        Ok(Oid(domain_digest(
            REGULATORY_EDIT_REPORT_FORMAT,
            &[&self.canonical_bytes()?],
        )))
    }
}

fn eval_linear_terms(
    terms: &[FfiecEditTerm],
    line_map: &BTreeMap<(&str, usize, u32), i128>,
    col_idx: usize,
    col_label: &str,
    unit_id: u32,
    edit_id: &str,
) -> Result<i128, StatementError> {
    if terms.is_empty() || terms.len() > MAX_EDIT_TERMS {
        return Err(StatementError::Definition(format!(
            "edit `{edit_id}` requires 1..=32 linear terms"
        )));
    }
    let mut sum = 0i128;
    for term in terms {
        if term.weight != 1 && term.weight != -1 {
            return Err(StatementError::Definition(format!(
                "edit `{edit_id}` has invalid term weight {} on `{}`",
                term.weight, term.line_code
            )));
        }
        let val = *line_map
            .get(&(term.line_code.as_str(), col_idx, unit_id))
            .ok_or_else(|| {
                StatementError::Input(format!(
                    "edit `{edit_id}` references line `{}` not present in statement",
                    term.line_code
                ))
            })?;
        let signed = if term.weight == 1 {
            val
        } else {
            val.checked_neg().ok_or_else(|| StatementError::Overflow {
                line: term.line_code.clone(),
                column: col_label.to_string(),
                unit_id,
            })?
        };
        sum = sum.checked_add(signed).ok_or_else(|| StatementError::Overflow {
            line: term.line_code.clone(),
            column: col_label.to_string(),
            unit_id,
        })?;
    }
    Ok(sum)
}

/// Evaluate a slice of [`FfiecEditRule`]s against an evaluated [`Statement`].
///
/// Any failed `Validity` edit returns an error unless `allow_validity_failures` is set;
/// when all validity edits pass, returns a certified [`RegulatoryEditReport`].
pub fn evaluate_regulatory_edits(
    statement: &Statement,
    form_at_quarter: &str,
    edits: &[FfiecEditRule],
) -> Result<RegulatoryEditReport, StatementError> {
    let schedule_digest = Oid(domain_digest(
        crate::OUTPUT_FORMAT.as_bytes(),
        &[&statement.canonical_bytes()?],
    ));
    let mut line_map: BTreeMap<(&str, usize, u32), i128> = BTreeMap::new();
    let mut unit_ids = BTreeSet::new();
    for line in &statement.lines {
        unit_ids.insert(line.unit_id);
        for (col_idx, &val) in line.amounts.iter().enumerate() {
            line_map.insert((line.code.as_str(), col_idx, line.unit_id), val);
        }
    }

    let mut rows = Vec::new();
    let mut validity_passed = 0usize;
    let mut validity_failed = 0usize;
    let mut quality_passed = 0usize;
    let mut quality_failed = 0usize;

    for edit in edits {
        for (col_idx, col) in statement.columns.iter().enumerate() {
            for &unit_id in &unit_ids {
                let lhs = eval_linear_terms(
                    &edit.lhs_terms,
                    &line_map,
                    col_idx,
                    &col.label,
                    unit_id,
                    &edit.edit_id,
                )?;
                let rhs = eval_linear_terms(
                    &edit.rhs_terms,
                    &line_map,
                    col_idx,
                    &col.label,
                    unit_id,
                    &edit.edit_id,
                )?;
                let delta = lhs.checked_sub(rhs).ok_or_else(|| StatementError::Overflow {
                    line: edit.edit_id.clone(),
                    column: col.label.clone(),
                    unit_id,
                })?;
                let passed = match edit.operator {
                    FfiecEditOperator::Equals => lhs == rhs,
                    FfiecEditOperator::GreaterOrEqual => lhs >= rhs,
                    FfiecEditOperator::LessOrEqual => lhs <= rhs,
                };
                match (edit.kind, passed) {
                    (FfiecEditKind::Validity, true) => validity_passed += 1,
                    (FfiecEditKind::Validity, false) => validity_failed += 1,
                    (FfiecEditKind::Quality, true) => quality_passed += 1,
                    (FfiecEditKind::Quality, false) => quality_failed += 1,
                }
                if rows.len() >= MAX_EDIT_CHECK_ROWS {
                    return Err(StatementError::Input(
                        "regulatory edit report exceeds maximum row limit".into(),
                    ));
                }
                rows.push(RegulatoryEditCheckRow {
                    edit_id: edit.edit_id.clone(),
                    kind: edit.kind,
                    column_label: col.label.clone(),
                    unit_id,
                    lhs_mantissa: lhs,
                    operator: edit.operator,
                    rhs_mantissa: rhs,
                    delta_mantissa: delta,
                    passed,
                });
            }
        }
    }

    Ok(RegulatoryEditReport {
        form_at_quarter: form_at_quarter.to_string(),
        schedule_digest,
        validity_passed,
        validity_failed,
        quality_passed,
        quality_failed,
        rows,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Account, AccountBalance, ColumnInput};
    use fa_model::Id128;
    use fa_time::DateDay;

    #[test]
    fn call_report_rc_ri_and_fr_y9c_hc_definitions_evaluate_and_pass_ffiec_edits() {
        let rc = RegulatoryScheduleDefinition::ffiec_041_schedule_rc_2026q1();
        let ri = RegulatoryScheduleDefinition::ffiec_041_schedule_ri_2026q1();
        let hc = RegulatoryScheduleDefinition::fr_y9c_schedule_hc_2026q1();

        for sched in [&rc, &ri, &hc] {
            let bytes = sched.canonical_bytes().unwrap();
            assert_eq!(
                RegulatoryScheduleDefinition::decode_canonical(&bytes).unwrap(),
                *sched
            );
        }

        let accounts = vec![
            Account {
                id: 1,
                code: "1010".into(),
                name: "Vault Cash and Fed Reserve Noninterest".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 2,
                code: "1110".into(),
                name: "Interest-Bearing Fed Balances".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 3,
                code: "1210".into(),
                name: "HTM Treasury Securities".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 4,
                code: "1310".into(),
                name: "AFS Agency MBS".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 5,
                code: "1410".into(),
                name: "Commercial & Industrial Loans".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 6,
                code: "1510".into(),
                name: "Allowance for Credit Losses".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 7,
                code: "1610".into(),
                name: "Bank Premises and Equipment".into(),
                account_type: 1,
                is_leaf: true,
            },
            Account {
                id: 8,
                code: "2010".into(),
                name: "Demand Deposits (DDA)".into(),
                account_type: 2,
                is_leaf: true,
            },
            Account {
                id: 9,
                code: "2310".into(),
                name: "FHLB Advances".into(),
                account_type: 2,
                is_leaf: true,
            },
            Account {
                id: 10,
                code: "2610".into(),
                name: "Accrued Interest Payable".into(),
                account_type: 2,
                is_leaf: true,
            },
            Account {
                id: 11,
                code: "3010".into(),
                name: "Common Stock".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 12,
                code: "3110".into(),
                name: "Capital Surplus".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 13,
                code: "3210".into(),
                name: "Retained Earnings".into(),
                account_type: 3,
                is_leaf: true,
            },
            Account {
                id: 14,
                code: "4010".into(),
                name: "Loan Interest Income".into(),
                account_type: 4,
                is_leaf: true,
            },
            Account {
                id: 15,
                code: "4110".into(),
                name: "Securities Interest Income".into(),
                account_type: 4,
                is_leaf: true,
            },
            Account {
                id: 16,
                code: "4210".into(),
                name: "Service Charges on Deposit Accounts".into(),
                account_type: 4,
                is_leaf: true,
            },
            Account {
                id: 17,
                code: "5010".into(),
                name: "Deposit Interest Expense".into(),
                account_type: 5,
                is_leaf: true,
            },
            Account {
                id: 18,
                code: "5110".into(),
                name: "Borrowing Interest Expense".into(),
                account_type: 5,
                is_leaf: true,
            },
            Account {
                id: 19,
                code: "5210".into(),
                name: "Provision for Credit Losses".into(),
                account_type: 5,
                is_leaf: true,
            },
            Account {
                id: 20,
                code: "6010".into(),
                name: "Salaries and Employee Benefits".into(),
                account_type: 5,
                is_leaf: true,
            },
            Account {
                id: 21,
                code: "8010".into(),
                name: "Applicable Income Taxes".into(),
                account_type: 5,
                is_leaf: true,
            },
        ];

        // Total assets = 50_000 + 100_000 + 80_000 + 120_000 + (600_000 - 10_000) + 60_000 = 1_000_000
        // Total liabilities = 750_000 (deposits) + 100_000 (FHLB) + 20_000 (other) = 870_000
        // Net income = (30_000 + 10_000 - (8_000 + 2_000)) - 3_000 + 5_000 - 12_000 - 4_000 = 16_000
        // Equity = 40_000 (common) + 50_000 (surplus) + 24_000 (prior RE) + 16_000 (current NI) = 130_000
        // Total L + E = 870_000 + 130_000 = 1_000_000
        let balances = vec![
            AccountBalance { account_id: 1, unit_id: 1, debits: 5_000_000, credits: 0 },
            AccountBalance { account_id: 2, unit_id: 1, debits: 10_000_000, credits: 0 },
            AccountBalance { account_id: 3, unit_id: 1, debits: 8_000_000, credits: 0 },
            AccountBalance { account_id: 4, unit_id: 1, debits: 12_000_000, credits: 0 },
            AccountBalance { account_id: 5, unit_id: 1, debits: 60_000_000, credits: 0 },
            AccountBalance { account_id: 6, unit_id: 1, debits: 0, credits: 1_000_000 },
            AccountBalance { account_id: 7, unit_id: 1, debits: 6_000_000, credits: 0 },
            AccountBalance { account_id: 8, unit_id: 1, debits: 0, credits: 75_000_000 },
            AccountBalance { account_id: 9, unit_id: 1, debits: 0, credits: 10_000_000 },
            AccountBalance { account_id: 10, unit_id: 1, debits: 0, credits: 2_000_000 },
            AccountBalance { account_id: 11, unit_id: 1, debits: 0, credits: 4_000_000 },
            AccountBalance { account_id: 12, unit_id: 1, debits: 0, credits: 5_000_000 },
            AccountBalance { account_id: 13, unit_id: 1, debits: 0, credits: 2_400_000 },
            AccountBalance { account_id: 14, unit_id: 1, debits: 0, credits: 3_000_000 },
            AccountBalance { account_id: 15, unit_id: 1, debits: 0, credits: 1_000_000 },
            AccountBalance { account_id: 16, unit_id: 1, debits: 0, credits: 500_000 },
            AccountBalance { account_id: 17, unit_id: 1, debits: 800_000, credits: 0 },
            AccountBalance { account_id: 18, unit_id: 1, debits: 200_000, credits: 0 },
            AccountBalance { account_id: 19, unit_id: 1, debits: 300_000, credits: 0 },
            AccountBalance { account_id: 20, unit_id: 1, debits: 1_200_000, credits: 0 },
            AccountBalance { account_id: 21, unit_id: 1, debits: 400_000, credits: 0 },
        ];

        let rc_input = StatementInput {
            book_id: Id128([1; 16]),
            branch_id: Id128([0; 16]),
            known_at: 42,
            accounts: accounts.clone(),
            units: vec![1],
            columns: vec![ColumnInput {
                label: "2026Q1".into(),
                periods: vec!["2026-Q1".into()],
                effective_from: None,
                effective_through: DateDay::from_ymd(2026, 3, 31).unwrap(),
                balances: balances.clone(),
            }],
        };

        let rc_stmt = rc.evaluate(&rc_input).unwrap();
        let rc_edits = regulatory_edits("FFIEC041:RC@2026Q1").unwrap();
        let rc_edit_report =
            evaluate_regulatory_edits(&rc_stmt, "FFIEC041:RC@2026Q1", &rc_edits).unwrap();
        assert_eq!(rc_edit_report.validity_passed, 3);
        assert_eq!(rc_edit_report.validity_failed, 0);
        assert_eq!(rc_edit_report.quality_passed, 1);
        assert_eq!(rc_edit_report.quality_failed, 0);
        assert!(rc_edit_report.certificate_digest().is_ok());

        let ri_input = StatementInput {
            book_id: Id128([1; 16]),
            branch_id: Id128([0; 16]),
            known_at: 42,
            accounts: accounts.clone(),
            units: vec![1],
            columns: vec![ColumnInput {
                label: "2026Q1".into(),
                periods: vec!["2026-Q1".into()],
                effective_from: Some(DateDay::from_ymd(2026, 1, 1).unwrap()),
                effective_through: DateDay::from_ymd(2026, 3, 31).unwrap(),
                balances: balances.clone(),
            }],
        };
        let ri_stmt = ri.evaluate(&ri_input).unwrap();
        let ri_edits = regulatory_edits("FFIEC041:RI@2026Q1").unwrap();
        let ri_edit_report =
            evaluate_regulatory_edits(&ri_stmt, "FFIEC041:RI@2026Q1", &ri_edits).unwrap();
        assert_eq!(ri_edit_report.validity_passed, 2);
        assert_eq!(ri_edit_report.validity_failed, 0);

        let hc_stmt = hc.evaluate(&rc_input).unwrap();
        let hc_edits = regulatory_edits("FRY9C@2026Q1").unwrap();
        let hc_edit_report =
            evaluate_regulatory_edits(&hc_stmt, "FRY9C@2026Q1", &hc_edits).unwrap();
        assert_eq!(hc_edit_report.validity_passed, 2);
        assert_eq!(hc_edit_report.validity_failed, 0);
    }
}
