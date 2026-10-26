//! `books/<stem>.toml`: one book variant of a case (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §3.2, §3.2a, §3.2b; bead fa-yugf.4, A1b).
//!
//! A book variant is the explicit, checkable encoding the runner replays:
//! the book's context, its periods, principals, accounts, parties and
//! documents, the intents with their legs, the restatement cases, and the
//! documented history as one ordered `[[step]]` array (the TOML subset keeps
//! no order between arrays of different names). Tables cannot nest, so legs,
//! steps and branch classes are foreign-key rows.
//!
//! [`load_book`] refuses every row that does not resolve: a foreign key that
//! names nothing, an intent whose declared legs do not balance per unit in
//! exact integers at the unit's scale ([`super::amount`]), a step whose `ref`
//! does not fit its kind, an id that breaks plan §3.2b. Rows whose resolution
//! needs the expectations (A1c) are checked for form only: a
//! `finding_review` or `assert_balance` ref, an `engagement_file` `finding:`
//! ref beyond its earlier `finding_record` step.

use std::collections::{BTreeMap, BTreeSet};

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::amount::{UnitTotals, format_amount, parse_amount};
use super::error::{LoadError, LoadErrorKind};
use super::fact::{Fact, Provenance, Value};
use super::fields::{Row, is_date};
use super::roles::Roles;
use super::rows::{row_key_line, row_line};
use super::source::{Source, put, put_opt, put_strs};

closed_set! {
    /// The kind of a book variant: the stem's prefix (plan §3.2b).
    VariantKind {
        Native => "native",
        Migration => "migration",
        Statement => "statement",
        Ledger => "ledger",
    }
}

closed_set! {
    /// A leg's side.
    Side {
        Dr => "Dr",
        Cr => "Cr",
    }
}

closed_set! {
    /// How a superseding intent relates to its target (`entry_classes.toml`
    /// `supersession`).
    TargetKind {
        Reverses => "reverses",
        Restates => "restates",
        Revises => "revises",
        Reclassifies => "reclassifies",
    }
}

closed_set! {
    /// The recorded coordinate a `finding_record` step reads at.
    KnownAt {
        Head => "head",
        PreCase => "pre_case",
    }
}

closed_set! {
    /// What a step of the documented history does.
    StepKind {
        Intent => "intent",
        Batch => "batch",
        Allocate => "allocate",
        PeriodOpen => "period_open",
        PeriodSoftClose => "period_soft_close",
        PeriodClose => "period_close",
        PeriodLock => "period_lock",
        Issue => "issue",
        AssertBalance => "assert_balance",
        ScenarioFork => "scenario_fork",
        ScenarioRun => "scenario_run",
        ScenarioDiff => "scenario_diff",
        CaseOpen => "case_open",
        CaseDetermine => "case_determine",
        CaseRehearse => "case_rehearse",
        CaseApprove => "case_approve",
        CasePost => "case_post",
        CaseDisclose => "case_disclose",
        CaseClose => "case_close",
        Checkpoint => "checkpoint",
        CheckpointWitness => "checkpoint_witness",
        FindingRecord => "finding_record",
        FindingReview => "finding_review",
        EngagementFile => "engagement_file",
        FillerBatch => "filler_batch",
        MigrateOpen => "migrate_open",
        MigrateStage => "migrate_stage",
        MigrateFinalize => "migrate_finalize",
        MigrateImport => "migrate_import",
        EventRecord => "event_record",
        RuleCheck => "rule_check",
        RulePropose => "rule_propose",
        RuleBacktest => "rule_backtest",
    }
}

impl StepKind {
    /// Whether the step runs intents (and takes their principal).
    #[must_use]
    pub const fn runs_intents(self) -> bool {
        matches!(self, Self::Intent | Self::Batch | Self::Allocate)
    }

    /// The role label a step runs as when it names none (plan §2.7, §12.7).
    #[must_use]
    pub const fn default_principal(self) -> Option<&'static str> {
        match self {
            Self::FindingReview => Some("case-second-reader"),
            Self::CheckpointWitness => Some("examiner-witness"),
            _ => None,
        }
    }

    const fn is_case(self) -> bool {
        matches!(
            self,
            Self::CaseOpen
                | Self::CaseDetermine
                | Self::CaseRehearse
                | Self::CaseApprove
                | Self::CasePost
                | Self::CaseDisclose
                | Self::CaseClose
        )
    }

    const fn is_period(self) -> bool {
        matches!(
            self,
            Self::PeriodOpen | Self::PeriodSoftClose | Self::PeriodClose | Self::PeriodLock
        )
    }
}

closed_set! {
    /// The closed branch-attribute enum (plan §2.6).
    BranchAttribute {
        EncodingOrigin => "encoding_origin",
        ApprovalEncoding => "approval_encoding",
        EntryClass => "entry_class",
        ReclassificationTarget => "reclassification_target",
        PeriodStateAtCommit => "period_state_at_commit",
        EffectiveDate => "effective_date",
        DocumentDate => "document_date",
        AmountPrecision => "amount_precision",
        LegSplit => "leg_split",
        EntryDecomposition => "entry_decomposition",
        EvidenceAttached => "evidence_attached",
        ApprovalsRecorded => "approvals_recorded",
        CapabilityGrants => "capability_grants",
        ActingPrincipal => "acting_principal",
        AccountLifecycle => "account_lifecycle",
        PartyAndDimensionValues => "party_and_dimension_values",
        ChartRoleMapping => "chart_role_mapping",
        CaseDeterminationDate => "case_determination_date",
    }
}

closed_set! {
    /// The party kinds `fa party add` accepts (`fa_model::PartyKind`).
    PartyKind {
        Customer => "Customer",
        Vendor => "Vendor",
        Employee => "Employee",
        Bank => "Bank",
        RelatedEntity => "RelatedEntity",
        BeneficialOwner => "BeneficialOwner",
        Regulator => "Regulator",
        Counterparty => "Counterparty",
    }
}

closed_set! {
    /// `fa party relate --kind`.
    RelationKind {
        Owns => "owns",
        Controls => "controls",
        Related => "related",
    }
}

closed_set! {
    /// `fa case open --kind`.
    RestatementKind {
        Restatement => "Restatement",
        Revision => "Revision",
        PriorPeriodAdjustment => "PriorPeriodAdjustment",
        PolicyChangeRetrospective => "PolicyChangeRetrospective",
    }
}

closed_set! {
    /// The kernel's period kinds (`fa_time::PeriodKind`).
    PeriodKind {
        Normal => "Normal",
        Adjustment => "Adjustment",
        Opening => "Opening",
        Closing => "Closing",
        Historical => "Historical",
    }
}

closed_set! {
    /// `fa event record --kind`.
    EventKind {
        Sale => "sale",
        Purchase => "purchase",
        Receipt => "receipt",
        Payment => "payment",
        Shipment => "shipment",
        Return => "return",
        Accrual => "accrual",
        Depreciation => "depreciation",
    }
}

closed_set! {
    /// `fa migrate import` formats.
    ImportFormat {
        QuickbooksIif => "quickbooks-iif",
        QuickbooksCsv => "quickbooks-csv",
        XeroCsv => "xero-csv",
        NetsuiteCsv => "netsuite-csv",
        Csv => "csv",
        Beancount => "beancount",
        Hledger => "hledger",
    }
}

closed_set! {
    /// An allocation's source side, beside an explicit total.
    AllocationSide {
        Debit => "debit",
        Credit => "credit",
    }
}

closed_set! {
    /// How the runner drives the book (the CLI's embedded owner, or MCP).
    Posture {
        EmbeddedOwner => "embedded-owner",
        Mcp => "mcp",
    }
}

/// Room an authored idempotency key leaves for A7c's per-cell suffix
/// (`.<12 hex>`, 13 bytes) under `max_idempotency_key_bytes`.
pub const CELL_KEY_SUFFIX_BYTES: usize = 13;

/// One book variant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookVariant {
    /// The file's stem (`native`, `statement-bridge`, …).
    pub stem: String,
    pub kind: VariantKind,
    pub book: BookHeader,
    pub periods: Vec<PeriodDef>,
    pub principals: Vec<PrincipalDef>,
    pub accounts: Vec<AccountDef>,
    pub parties: Vec<PartyDef>,
    pub documents: Vec<DocumentDef>,
    pub intents: Vec<IntentDef>,
    pub cases: Vec<CaseDef>,
    pub legs: Vec<LegDef>,
    pub steps: Vec<StepDef>,
    pub branch_classes: Vec<BranchClassDef>,
    pub defaults: Vec<DefaultDef>,
    pub ledger_maps: Vec<LedgerMapDef>,
    pub events: Vec<EventDef>,
    pub migration_imports: Vec<MigrationImportDef>,
}

/// `[book]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BookHeader {
    pub variant: String,
    pub opening_date: String,
    pub calendar: String,
    pub base_unit: String,
    pub posture: String,
    /// `<code>[:<name>]` tokens, as authored.
    pub entities: Option<Vec<String>>,
    /// `<from>|<kind>:<to>;basis=…;valid_from=…` tokens, as authored.
    pub entity_relations: Option<Vec<String>>,
    /// `entity_relations` parsed.
    pub relations: Vec<EntityRelation>,
}

impl BookHeader {
    /// The legal-entity codes `entities` declares.
    #[must_use]
    pub fn entity_codes(&self) -> Vec<&str> {
        self.entities
            .iter()
            .flatten()
            .map(|t| t.split_once(':').map_or(t.as_str(), |(c, _)| c))
            .collect()
    }
}

/// A relation between two of the book's legal entities.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntityRelation {
    pub from: String,
    pub relation: Relation,
}

/// One `fa party relate` edge: `<kind>:<to>;basis=<code>;valid_from=<date>
/// [;valid_to=<date>][;pct=<num>/<den>]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Relation {
    pub kind: RelationKind,
    pub to: String,
    pub basis: String,
    pub valid_from: String,
    pub valid_to: Option<String>,
    pub pct: Option<(u128, u128)>,
}

/// `[[period]]`: a harness label the runner maps to the code `fa period
/// create` reports; `start` and `end` are inclusive days.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeriodDef {
    pub code: String,
    pub start: String,
    pub end: String,
    pub fiscal_year: i128,
    pub kind: String,
    pub line: Option<usize>,
}

impl PeriodDef {
    #[must_use]
    pub fn contains(&self, day: &str) -> bool {
        self.start.as_str() <= day && day <= self.end.as_str()
    }
}

/// `[[principal]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalDef {
    pub label: String,
    pub profile: String,
    pub grants: Vec<String>,
    pub line: Option<usize>,
}

/// `[[account]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountDef {
    pub code: String,
    pub name_fact: String,
    pub account_type: String,
    pub role: Option<String>,
    pub opened: String,
    pub closed: Option<String>,
    pub role_map_rule: Option<String>,
    pub line: Option<usize>,
}

/// `[[party]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartyDef {
    pub id: String,
    pub label: String,
    pub kind: String,
    /// As authored.
    pub relations_raw: Option<Vec<String>>,
    pub relations: Vec<Relation>,
    pub line: Option<usize>,
}

/// `[[document]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DocumentDef {
    pub id: String,
    pub stub_of: String,
    pub grade: String,
    pub reviewed_by: Option<String>,
    pub line: Option<usize>,
}

/// `[[intent]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntentDef {
    pub id: String,
    pub fact: String,
    pub class: String,
    pub principal: String,
    pub effective_date: String,
    pub document_date: Option<String>,
    pub memo: Option<String>,
    pub evidence: Option<String>,
    pub idempotency_key: Option<String>,
    pub target: Option<String>,
    pub target_kind: Option<String>,
    pub reason: Option<String>,
    pub scenario: Option<String>,
    pub allocation_law: Option<String>,
    pub allocation_total: Option<String>,
    pub allocation_targets: Option<Vec<String>>,
    pub allocation_source: Option<String>,
    pub allocation_source_side: Option<String>,
    pub source_entered_by: Option<String>,
    pub source_approved_by: Option<String>,
    pub line: Option<usize>,
}

impl IntentDef {
    /// Whether the intent is planned for `fa allocate`.
    #[must_use]
    pub fn is_allocation(&self) -> bool {
        self.allocation_law.is_some()
    }

    /// Whether the intent is a case Δ (`restates` or `revises`, plan §3.2b).
    #[must_use]
    pub fn is_delta(&self) -> bool {
        matches!(
            self.target_kind.as_deref().and_then(TargetKind::parse),
            Some(TargetKind::Restates | TargetKind::Revises)
        )
    }
}

/// `[[case]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaseDef {
    pub id: String,
    pub kind: String,
    pub periods: Vec<String>,
    pub determined_on: String,
    pub authority: String,
    pub disclosure: String,
    pub approvers: Vec<String>,
    pub poster: String,
    pub line: Option<usize>,
}

/// `[[leg]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegDef {
    pub intent: String,
    pub ordinal: i128,
    pub account: String,
    pub side: String,
    pub amount_literal: String,
    pub amount_rule: String,
    pub unit: String,
    pub party: Option<String>,
    pub entity: Option<String>,
    pub line: Option<usize>,
}

/// `[[step]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepDef {
    pub seq: i128,
    pub kind: String,
    pub reference: String,
    pub known_at: Option<String>,
    pub branch_class: Option<String>,
    pub principal: Option<String>,
    pub approvers: Option<Vec<String>>,
    pub params: Option<Vec<String>>,
    pub evidence: Option<String>,
    pub asserts: Option<String>,
    pub document: Option<String>,
    pub line: Option<usize>,
}

impl StepDef {
    #[must_use]
    pub fn step_kind(&self) -> Option<StepKind> {
        StepKind::parse(&self.kind)
    }
}

/// `[[branch_class]]`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchClassDef {
    pub id: String,
    pub attribute: String,
    pub rule: String,
    pub values: Vec<String>,
    pub line: Option<usize>,
}

/// `[[default]]`: a declared default encoding (plan §2.6 rule 2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultDef {
    pub attribute: String,
    pub rule: String,
    pub rationale: String,
    pub line: Option<usize>,
}

/// `[[ledger_map]]` (M0, `ledger` stems only).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LedgerMapDef {
    pub source: String,
    pub account: String,
    pub book_account: String,
    pub party: String,
    pub cash_account: String,
    pub transfer_account: String,
    pub amount_columns: Vec<String>,
    pub line: Option<usize>,
}

/// `[[event]]` (L3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventDef {
    pub id: String,
    pub kind: String,
    pub occurred_on: String,
    pub evidence: Vec<String>,
    pub participants: Option<Vec<String>>,
    pub resource_label: Option<String>,
    pub resource_amount_literal: Option<String>,
    pub resource_amount_rule: Option<String>,
    pub resource_unit: Option<String>,
    pub line: Option<usize>,
}

/// `[[migration_import]]` (M6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MigrationImportDef {
    pub id: String,
    pub run: i128,
    pub source: String,
    pub format: String,
    pub account_map: Vec<String>,
    pub column_map: Option<String>,
    pub default_unit: Option<String>,
    pub entry_periods: Option<Vec<String>>,
    pub line: Option<usize>,
}

/// What a book resolves against: the case's other files.
#[derive(Clone, Copy, Debug)]
pub struct CaseView<'a> {
    pub sources: &'a [Source],
    pub facts: &'a [Fact],
    pub values: &'a [Value],
    pub roles: &'a Roles,
    /// The `variants` `case.toml` declares (`None` when it did not load).
    pub variants: Option<&'a [String]>,
    /// Every path among the case's files (rule sources live at `rules/…`).
    pub files: &'a [&'a str],
}

/// The registry rows a book resolves against.
#[derive(Default)]
pub(crate) struct Registries {
    unit_scales: BTreeMap<String, u8>,
    supersession: BTreeMap<String, String>,
    account_types: BTreeSet<String>,
    account_roles: Vec<fa_registry::account_roles::AccountRole>,
    reasons: BTreeSet<(String, String)>,
    bases: BTreeSet<String>,
    procedures: Option<fa_registry::procedures::Procedures>,
    ops: BTreeSet<String>,
    profiles: BTreeSet<String>,
    grades: BTreeSet<String>,
    allocation_laws: BTreeSet<String>,
    max_key_bytes: usize,
    max_memo_bytes: usize,
}

impl Registries {
    pub(crate) fn embedded(errs: &mut Vec<LoadError>) -> Self {
        let mut r = Self::default();
        let mut fail = |file: &str, e: &dyn core::fmt::Display| {
            errs.push(LoadError {
                file: format!("registries/{file}"),
                line: None,
                kind: LoadErrorKind::Toml,
                row: None,
                detail: e.to_string(),
            });
        };
        match fa_registry::units_embedded() {
            Ok(rows) => {
                let mut best: BTreeMap<String, (u16, u8)> = BTreeMap::new();
                for u in rows {
                    let e = best.entry(u.code).or_insert((u.version, u.scale));
                    if u.version >= e.0 {
                        *e = (u.version, u.scale);
                    }
                }
                r.unit_scales = best.into_iter().map(|(k, (_, s))| (k, s)).collect();
            }
            Err(e) => fail("units.toml", &e),
        }
        match fa_registry::EntryClasses::embedded() {
            Ok(c) => {
                r.supersession = c
                    .rows
                    .into_iter()
                    .filter(|row| matches!(row.kind, fa_registry::ClassKind::Posting))
                    .map(|row| (row.name, row.supersession))
                    .collect();
            }
            Err(e) => fail("entry_classes.toml", &e),
        }
        match fa_registry::account_types_embedded() {
            Ok(rows) => r.account_types = rows.into_iter().map(|t| t.name).collect(),
            Err(e) => fail("account_types.toml", &e),
        }
        match fa_registry::account_roles::AccountRoles::embedded() {
            Ok(roles) => r.account_roles = roles.rows,
            Err(e) => fail("account_roles.toml", &e),
        }
        match fa_registry::reason_codes::ReasonCodes::embedded() {
            Ok(codes) => {
                r.reasons = codes.rows.into_iter().map(|c| (c.scope, c.name)).collect();
            }
            Err(e) => fail("reason_codes.toml", &e),
        }
        match fa_registry::g0::RelationshipBases::embedded() {
            Ok(b) => r.bases = b.rows.into_iter().map(|row| row.code).collect(),
            Err(e) => fail("relationship_bases.toml", &e),
        }
        match fa_registry::procedures::Procedures::embedded() {
            Ok(p) => r.procedures = Some(p),
            Err(e) => fail("procedures.toml", &e),
        }
        match fa_registry::CapabilityCaveats::embedded() {
            Ok(c) => {
                r.ops = c.ops.into_iter().map(|o| o.name).collect();
                r.profiles = ["Human", "Agent", "System"]
                    .into_iter()
                    .map(str::to_string)
                    .chain(c.profiles.into_iter().map(|p| p.name))
                    .collect();
            }
            Err(e) => fail("capability_caveats.toml", &e),
        }
        match fa_registry::evidence_policy::EvidencePolicy::embedded() {
            Ok(p) => r.grades = p.grades.into_iter().map(|g| g.name).collect(),
            Err(e) => fail("evidence_policy.toml", &e),
        }
        for (family, array, text) in fa_registry::LAW_REGISTRIES {
            if family != "allocation" {
                continue;
            }
            match fa_registry::toml::parse(text) {
                Ok(doc) => {
                    r.allocation_laws = doc
                        .arrays
                        .get(array)
                        .into_iter()
                        .flatten()
                        .filter_map(|t| t.get("name").and_then(TomlValue::as_str))
                        .map(str::to_string)
                        .collect();
                }
                Err(e) => fail("allocation_laws.toml", &e.message),
            }
        }
        match fa_registry::limits_embedded() {
            Ok(limits) => {
                let get = |k: &str| {
                    limits
                        .get(k)
                        .and_then(|v| usize::try_from(*v).ok())
                        .unwrap_or(0)
                };
                r.max_key_bytes = get("max_idempotency_key_bytes");
                r.max_memo_bytes = get("max_memo_bytes");
            }
            Err(e) => fail("limits.toml", &e),
        }
        r
    }
}

/// The arrays a book file may hold.
const ARRAYS: [&str; 14] = [
    "period",
    "principal",
    "account",
    "party",
    "document",
    "intent",
    "case",
    "leg",
    "step",
    "branch_class",
    "default",
    "ledger_map",
    "event",
    "migration_import",
];

/// The kind a stem names, if it is `<kind>` or `<kind>-<suffix>` with a
/// suffix of lower-case letters, digits and `-`.
#[must_use]
pub fn stem_kind(stem: &str) -> Option<VariantKind> {
    let (kind, suffix) = match stem.split_once('-') {
        Some((k, s)) => (k, Some(s)),
        None => (stem, None),
    };
    if suffix.is_some_and(|s| {
        s.is_empty()
            || !s
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    }) {
        return None;
    }
    VariantKind::parse(kind)
}

/// Loads one book file of a loaded case.
///
/// # Errors
///
/// Every problem found, sorted by (file, line).
pub fn load_book(
    case: &super::Case,
    path: &str,
    text: &str,
) -> Result<BookVariant, Vec<LoadError>> {
    let paths: Vec<&str> = case.files.iter().map(String::as_str).collect();
    let view = CaseView {
        sources: &case.sources,
        facts: &case.facts,
        values: &case.values,
        roles: &case.roles,
        variants: Some(&case.header.variants),
        files: &paths,
    };
    let mut errs = Vec::new();
    let registries = Registries::embedded(&mut errs);
    let book = parse(&view, &registries, path, text, &mut errs);
    match book {
        Some(b) if errs.is_empty() => Ok(b),
        _ => {
            super::error::sort(&mut errs);
            Err(errs)
        }
    }
}

/// Parses and checks one book file, pushing every problem to `errs`.
pub(crate) fn parse(
    view: &CaseView<'_>,
    reg: &Registries,
    path: &str,
    text: &str,
    errs: &mut Vec<LoadError>,
) -> Option<BookVariant> {
    let file_err = |line: Option<usize>, kind: LoadErrorKind, detail: String| LoadError {
        file: path.to_string(),
        line,
        kind,
        row: None,
        detail,
    };
    let stem = path
        .strip_prefix("books/")
        .and_then(|p| p.strip_suffix(".toml"))
        .unwrap_or("");
    let Some(kind) = stem_kind(stem) else {
        errs.push(file_err(
            None,
            LoadErrorKind::BadStem,
            format!(
                "`{path}` is not books/<kind>[-<suffix>].toml with kind native, migration, statement or ledger"
            ),
        ));
        return None;
    };
    if let Some(variants) = view.variants
        && !variants.iter().any(|v| v == stem)
    {
        errs.push(file_err(
            None,
            LoadErrorKind::DanglingKey,
            format!("case.toml `variants` does not declare `{stem}`"),
        ));
    }
    let doc = match fa_registry::toml::parse(text) {
        Ok(doc) => doc,
        Err(e) => {
            errs.push(file_err(Some(e.line), LoadErrorKind::Toml, e.message));
            return None;
        }
    };
    for key in doc.root.keys() {
        errs.push(file_err(
            super::rows::root_key_line(text, key),
            LoadErrorKind::UnknownField,
            format!("unknown root key `{key}`"),
        ));
    }
    for name in doc.tables.keys().filter(|n| n.as_str() != "book") {
        errs.push(file_err(
            None,
            LoadErrorKind::UnknownField,
            format!("unknown table `[{name}]`"),
        ));
    }
    for name in doc.arrays.keys().filter(|n| !ARRAYS.contains(&n.as_str())) {
        errs.push(file_err(
            row_line(text, name, 0),
            LoadErrorKind::UnknownField,
            format!("unknown array `[[{name}]]`"),
        ));
    }
    let mut p = Parser {
        path,
        text,
        doc: &doc,
        errs,
    };
    let book = p.book(reg, stem)?;
    let mut b = BookVariant {
        stem: stem.to_string(),
        kind,
        book,
        periods: p.periods(),
        principals: p.principals(),
        accounts: p.accounts(),
        parties: Vec::new(),
        documents: p.documents(),
        intents: p.intents(kind),
        cases: p.cases(),
        legs: p.legs(),
        steps: p.steps(),
        branch_classes: p.branch_classes(),
        defaults: p.defaults(),
        ledger_maps: p.ledger_maps(),
        events: p.events(),
        migration_imports: p.migration_imports(),
    };
    b.parties = p.parties(reg);
    Check {
        view,
        reg,
        book: &b,
        path,
        text,
        errs: p.errs,
    }
    .run();
    Some(b)
}

struct Parser<'a, 'e> {
    path: &'a str,
    text: &'a str,
    doc: &'a Document,
    errs: &'e mut Vec<LoadError>,
}

impl<'a> Parser<'a, '_> {
    fn rows(&self, array: &str) -> &'a [Table] {
        self.doc.arrays.get(array).map(Vec::as_slice).unwrap_or(&[])
    }

    fn row(&self, array: &str, i: usize, table: &'a Table) -> Row<'a> {
        Row::new(self.path, row_line(self.text, array, i), table)
    }

    fn book(&mut self, reg: &Registries, stem: &str) -> Option<BookHeader> {
        let Some(table) = self.doc.tables.get("book") else {
            self.errs.push(LoadError {
                file: self.path.to_string(),
                line: None,
                kind: LoadErrorKind::MissingField,
                row: None,
                detail: "the `[book]` table is required".into(),
            });
            return None;
        };
        let line = self
            .text
            .lines()
            .position(|l| l.trim() == "[book]")
            .map(|n| n + 1);
        let mut r = Row::new(self.path, line, table);
        let errs = &mut *self.errs;
        let variant = r.req_str("variant", errs);
        let opening_date = r.req_str("opening_date", errs);
        let calendar = r.req_str("calendar", errs);
        let base_unit = r.req_str("base_unit", errs);
        let posture = r.req_str("posture", errs);
        let entities = r.opt_strs("entities", errs);
        let entity_relations = r.opt_strs("entity_relations", errs);
        r.finish(&[], " in `[book]`", errs);
        if variant != stem {
            errs.push(r.err(
                LoadErrorKind::BadStem,
                format!("`variant = \"{variant}\"` differs from the file's stem `{stem}`"),
            ));
        }
        if !is_date(&opening_date) {
            errs.push(r.err(
                LoadErrorKind::WrongType,
                "`opening_date` is a YYYY-MM-DD date",
            ));
        }
        if calendar != "custom" {
            errs.push(r.err(
                LoadErrorKind::UnknownValue,
                format!("`calendar = \"{calendar}\"`: case books use the `custom` calendar"),
            ));
        }
        if !reg.unit_scales.contains_key(&base_unit) {
            errs.push(r.err(
                LoadErrorKind::UnknownValue,
                format!("`base_unit = \"{base_unit}\"` is not a registered unit"),
            ));
        }
        if Posture::parse(&posture).is_none() {
            errs.push(r.err(
                LoadErrorKind::UnknownValue,
                format!("`posture = \"{posture}\"` is outside its closed set"),
            ));
        }
        let mut codes = BTreeSet::new();
        for token in entities.iter().flatten() {
            let code = token.split_once(':').map_or(token.as_str(), |(c, _)| c);
            if !is_word(code) {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    format!("entity `{token}` is not `<code>[:<name>]`"),
                ));
            } else if !codes.insert(code.to_string()) {
                errs.push(r.err(
                    LoadErrorKind::DuplicateLabel,
                    format!("entity code `{code}` is declared twice"),
                ));
            }
        }
        let mut relations = Vec::new();
        for token in entity_relations.iter().flatten() {
            let Some((from, rest)) = token.split_once('|') else {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    format!("entity relation `{token}` is not `<from>|<kind>:<to>;…`"),
                ));
                continue;
            };
            match parse_relation(rest, reg) {
                Ok(rel) => {
                    for end in [from, rel.to.as_str()] {
                        if !codes.contains(end) {
                            errs.push(r.err(
                                LoadErrorKind::DanglingKey,
                                format!(
                                    "entity relation `{token}` names `{end}`, which is not a `[book] entities` code"
                                ),
                            ));
                        }
                    }
                    if from == rel.to {
                        errs.push(r.err(
                            LoadErrorKind::WrongType,
                            format!("entity relation `{token}` joins an entity to itself"),
                        ));
                    }
                    if rel.kind == RelationKind::Owns
                        && !rel
                            .pct
                            .is_some_and(|(num, den)| den == 10_000 && num <= 10_000)
                    {
                        errs.push(r.err(
                            LoadErrorKind::UnknownValue,
                            format!(
                                "entity relation `{token}`: an owns stake is whole basis points, `pct=<bps>/10000` (fa consolidate refuses any other, FA-REF-194)"
                            ),
                        ));
                    }
                    relations.push(EntityRelation {
                        from: from.to_string(),
                        relation: rel,
                    });
                }
                Err((kind, detail)) => {
                    errs.push(r.err(kind, format!("entity relation `{token}`: {detail}")));
                }
            }
        }
        Some(BookHeader {
            variant,
            opening_date,
            calendar,
            base_unit,
            posture,
            entities,
            entity_relations,
            relations,
        })
    }

    fn periods(&mut self) -> Vec<PeriodDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("period").iter().enumerate() {
            let mut r = self.row("period", i, t);
            let errs = &mut *self.errs;
            let code = r.req_str("code", errs);
            let start = r.req_str("start", errs);
            let end = r.req_str("end", errs);
            let fiscal_year = r.req_int("fiscal_year", errs);
            let kind = r.req_str("kind", errs);
            r.finish(&[], " in `[[period]]`", errs);
            if !is_date(&start) || !is_date(&end) || start > end {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "`start` and `end` are YYYY-MM-DD dates with start ≤ end",
                ));
            }
            if PeriodKind::parse(&kind).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`kind = \"{kind}\"` is not a period kind"),
                ));
            }
            out.push(PeriodDef {
                code,
                start,
                end,
                fiscal_year,
                kind,
                line: r.line(),
            });
        }
        out
    }

    fn principals(&mut self) -> Vec<PrincipalDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("principal").iter().enumerate() {
            let mut r = self.row("principal", i, t);
            let errs = &mut *self.errs;
            let label = r.req_str("label", errs);
            let profile = r.req_str("profile", errs);
            let grants = r.req_strs("grants", errs);
            r.finish(&[], " in `[[principal]]`", errs);
            out.push(PrincipalDef {
                label,
                profile,
                grants,
                line: r.line(),
            });
        }
        out
    }

    fn accounts(&mut self) -> Vec<AccountDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("account").iter().enumerate() {
            let mut r = self.row("account", i, t);
            let errs = &mut *self.errs;
            let code = r.req_str("code", errs);
            let name_fact = r.req_str("name_fact", errs);
            let account_type = r.req_str("type", errs);
            let role = r.opt_str("role", errs);
            let opened = r.req_str("opened", errs);
            let closed = r.opt_str("closed", errs);
            let role_map_rule = r.opt_str("role_map_rule", errs);
            r.finish(&[], " in `[[account]]`", errs);
            if !is_date(&opened)
                || closed
                    .as_deref()
                    .is_some_and(|c| !c.is_empty() && !is_date(c))
            {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "`opened` (and a non-empty `closed`) are YYYY-MM-DD dates",
                ));
            }
            out.push(AccountDef {
                code,
                name_fact,
                account_type,
                role,
                opened,
                closed,
                role_map_rule,
                line: r.line(),
            });
        }
        out
    }

    fn parties(&mut self, reg: &Registries) -> Vec<PartyDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("party").iter().enumerate() {
            let mut r = self.row("party", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let label = r.req_str("label", errs);
            let kind = r.req_str("kind", errs);
            let relations_raw = r.opt_strs("relations", errs);
            r.finish(&[], " in `[[party]]`", errs);
            if PartyKind::parse(&kind).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`kind = \"{kind}\"` is not a party kind `fa party add` accepts"),
                ));
            }
            let mut relations = Vec::new();
            for token in relations_raw.iter().flatten() {
                match parse_relation(token, reg) {
                    Ok(rel) => {
                        if rel.kind == RelationKind::Owns && rel.pct.is_none() {
                            errs.push(r.err(
                                LoadErrorKind::MissingField,
                                format!(
                                    "relation `{token}`: an owns edge needs `;pct=<num>/<den>`"
                                ),
                            ));
                        }
                        relations.push(rel);
                    }
                    Err((k, detail)) => {
                        errs.push(r.err(k, format!("relation `{token}`: {detail}")))
                    }
                }
            }
            out.push(PartyDef {
                id,
                label,
                kind,
                relations_raw,
                relations,
                line: r.line(),
            });
        }
        out
    }

    fn documents(&mut self) -> Vec<DocumentDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("document").iter().enumerate() {
            let mut r = self.row("document", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let stub_of = r.req_str("stub_of", errs);
            let grade = r.req_str("grade", errs);
            let reviewed_by = r.opt_str("reviewed_by", errs);
            r.finish(&[], " in `[[document]]`", errs);
            out.push(DocumentDef {
                id,
                stub_of,
                grade,
                reviewed_by,
                line: r.line(),
            });
        }
        out
    }

    fn intents(&mut self, kind: VariantKind) -> Vec<IntentDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("intent").iter().enumerate() {
            let mut r = self.row("intent", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let fact = r.req_str("fact", errs);
            let class = r.req_str("class", errs);
            let principal = r.req_str("principal", errs);
            let effective_date = r.req_str("effective_date", errs);
            let document_date = r.opt_str("document_date", errs);
            let memo = r.opt_str("memo", errs);
            let evidence = r.opt_str("evidence", errs);
            let idempotency_key = r.opt_str("idempotency_key", errs);
            let target = r.opt_str("target", errs);
            let target_kind = r.opt_str("target_kind", errs);
            let reason = r.opt_str("reason", errs);
            let scenario = r.opt_str("scenario", errs);
            let allocation_law = r.opt_str("allocation_law", errs);
            let allocation_total = r.opt_str("allocation_total", errs);
            let allocation_targets = r.opt_strs("allocation_targets", errs);
            let allocation_source = r.opt_str("allocation_source", errs);
            let allocation_source_side = r.opt_str("allocation_source_side", errs);
            let (source_entered_by, source_approved_by) = if kind == VariantKind::Migration {
                (
                    r.opt_str("source_entered_by", errs),
                    r.opt_str("source_approved_by", errs),
                )
            } else {
                (None, None)
            };
            let context = if kind == VariantKind::Migration {
                " in `[[intent]]`"
            } else {
                " in `[[intent]]` (legacy attribution belongs to a migration stem; recorded time is never authored)"
            };
            r.finish(&[], context, errs);
            if !is_date(&effective_date)
                || document_date
                    .as_deref()
                    .is_some_and(|d| !d.is_empty() && !is_date(d))
            {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "`effective_date` (and a non-empty `document_date`) are YYYY-MM-DD dates",
                ));
            }
            out.push(IntentDef {
                id,
                fact,
                class,
                principal,
                effective_date,
                document_date,
                memo,
                evidence,
                idempotency_key,
                target,
                target_kind,
                reason,
                scenario,
                allocation_law,
                allocation_total,
                allocation_targets,
                allocation_source,
                allocation_source_side,
                source_entered_by,
                source_approved_by,
                line: r.line(),
            });
        }
        out
    }

    fn cases(&mut self) -> Vec<CaseDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("case").iter().enumerate() {
            let mut r = self.row("case", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let kind = r.req_str("kind", errs);
            let periods = r.req_strs("periods", errs);
            let determined_on = r.req_str("determined_on", errs);
            let authority = r.req_str("authority", errs);
            let disclosure = r.req_str("disclosure", errs);
            let approvers = r.req_strs("approvers", errs);
            let poster = r.req_str("poster", errs);
            r.finish(&[], " in `[[case]]`", errs);
            if RestatementKind::parse(&kind).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`kind = \"{kind}\"` is not a case kind `fa case open` accepts"),
                ));
            }
            out.push(CaseDef {
                id,
                kind,
                periods,
                determined_on,
                authority,
                disclosure,
                approvers,
                poster,
                line: r.line(),
            });
        }
        out
    }

    fn legs(&mut self) -> Vec<LegDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("leg").iter().enumerate() {
            let mut r = self.row("leg", i, t);
            let errs = &mut *self.errs;
            let intent = r.req_str("intent", errs);
            let ordinal = r.req_int("ordinal", errs);
            let account = r.req_str("account", errs);
            let side = r.req_str("side", errs);
            let amount_literal = r.req_str("amount_literal", errs);
            let amount_rule = r.req_str("amount_rule", errs);
            let unit = r.req_str("unit", errs);
            let party = r.opt_str("party", errs);
            let entity = r.opt_str("entity", errs);
            r.finish(&[], " in `[[leg]]`", errs);
            if Side::parse(&side).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`side = \"{side}\"` is `Dr` or `Cr`"),
                ));
            }
            out.push(LegDef {
                intent,
                ordinal,
                account,
                side,
                amount_literal,
                amount_rule,
                unit,
                party,
                entity,
                line: r.line(),
            });
        }
        out
    }

    fn steps(&mut self) -> Vec<StepDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("step").iter().enumerate() {
            let mut r = self.row("step", i, t);
            let errs = &mut *self.errs;
            let seq = r.req_int("seq", errs);
            let kind = r.req_str("kind", errs);
            let reference = r.req_str("ref", errs);
            let known_at = r.opt_str("known_at", errs);
            let branch_class = r.opt_str("branch_class", errs);
            let principal = r.opt_str("principal", errs);
            let approvers = r.opt_strs("approvers", errs);
            let params = r.opt_strs("params", errs);
            let evidence = r.opt_str("evidence", errs);
            let asserts = r.opt_str("asserts", errs);
            let document = r.opt_str("document", errs);
            r.finish(&[], " in `[[step]]`", errs);
            if StepKind::parse(&kind).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`kind = \"{kind}\"` is not a step kind"),
                ));
            }
            out.push(StepDef {
                seq,
                kind,
                reference,
                known_at,
                branch_class,
                principal,
                approvers,
                params,
                evidence,
                asserts,
                document,
                line: r.line(),
            });
        }
        out
    }

    fn branch_classes(&mut self) -> Vec<BranchClassDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("branch_class").iter().enumerate() {
            let mut r = self.row("branch_class", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let attribute = r.req_str("attribute", errs);
            let rule = r.req_str("rule", errs);
            let values = r.req_strs("values", errs);
            r.finish(&[], " in `[[branch_class]]`", errs);
            if BranchAttribute::parse(&attribute).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`attribute = \"{attribute}\"` is outside the §2.6 enum"),
                ));
            }
            if values.is_empty() {
                errs.push(r.err(
                    LoadErrorKind::MissingField,
                    "a branch class lists its values",
                ));
            }
            out.push(BranchClassDef {
                id,
                attribute,
                rule,
                values,
                line: r.line(),
            });
        }
        out
    }

    fn defaults(&mut self) -> Vec<DefaultDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("default").iter().enumerate() {
            let mut r = self.row("default", i, t);
            let errs = &mut *self.errs;
            let attribute = r.req_str("attribute", errs);
            let rule = r.req_str("rule", errs);
            let rationale = r.req_str("rationale", errs);
            r.finish(&[], " in `[[default]]`", errs);
            out.push(DefaultDef {
                attribute,
                rule,
                rationale,
                line: r.line(),
            });
        }
        out
    }

    fn ledger_maps(&mut self) -> Vec<LedgerMapDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("ledger_map").iter().enumerate() {
            let mut r = self.row("ledger_map", i, t);
            let errs = &mut *self.errs;
            let source = r.req_str("source", errs);
            let account = r.req_str("account", errs);
            let book_account = r.req_str("book_account", errs);
            let party = r.req_str("party", errs);
            let cash_account = r.req_str("cash_account", errs);
            let transfer_account = r.req_str("transfer_account", errs);
            let amount_columns = r.req_strs("amount_columns", errs);
            r.finish(&[], " in `[[ledger_map]]`", errs);
            out.push(LedgerMapDef {
                source,
                account,
                book_account,
                party,
                cash_account,
                transfer_account,
                amount_columns,
                line: r.line(),
            });
        }
        out
    }

    fn events(&mut self) -> Vec<EventDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("event").iter().enumerate() {
            let mut r = self.row("event", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let kind = r.req_str("kind", errs);
            let occurred_on = r.req_str("occurred_on", errs);
            let evidence = r.req_strs("evidence", errs);
            let participants = r.opt_strs("participants", errs);
            let resource_label = r.opt_str("resource_label", errs);
            let resource_amount_literal = r.opt_str("resource_amount_literal", errs);
            let resource_amount_rule = r.opt_str("resource_amount_rule", errs);
            let resource_unit = r.opt_str("resource_unit", errs);
            r.finish(&[], " in `[[event]]`", errs);
            if EventKind::parse(&kind).is_none() {
                errs.push(r.err(
                    LoadErrorKind::UnknownValue,
                    format!("`kind = \"{kind}\"` is not a kind `fa event record` accepts"),
                ));
            }
            if !is_date(&occurred_on) {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "`occurred_on` is a YYYY-MM-DD date",
                ));
            }
            out.push(EventDef {
                id,
                kind,
                occurred_on,
                evidence,
                participants,
                resource_label,
                resource_amount_literal,
                resource_amount_rule,
                resource_unit,
                line: r.line(),
            });
        }
        out
    }

    fn migration_imports(&mut self) -> Vec<MigrationImportDef> {
        let mut out = Vec::new();
        for (i, t) in self.rows("migration_import").iter().enumerate() {
            let mut r = self.row("migration_import", i, t);
            let errs = &mut *self.errs;
            let id = r.req_str("id", errs);
            let run = r.req_int("run", errs);
            let source = r.req_str("source", errs);
            let format = r.req_str("format", errs);
            let account_map = r.req_strs("account_map", errs);
            let column_map = r.opt_str("column_map", errs);
            let default_unit = r.opt_str("default_unit", errs);
            let entry_periods = r.opt_strs("entry_periods", errs);
            r.finish(&[], " in `[[migration_import]]`", errs);
            out.push(MigrationImportDef {
                id,
                run,
                source,
                format,
                account_map,
                column_map,
                default_unit,
                entry_periods,
                line: r.line(),
            });
        }
        out
    }
}

/// Letters, digits, `_` and `-`.
fn is_word(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// One relation token after its `from` part: `<kind>:<to>;basis=<code>;
/// valid_from=<date>[;valid_to=<date>][;pct=<num>/<den>]`.
fn parse_relation(token: &str, reg: &Registries) -> Result<Relation, (LoadErrorKind, String)> {
    let mut parts = token.split(';');
    let head = parts.next().unwrap_or_default();
    let (kind_raw, to) = head.split_once(':').ok_or((
        LoadErrorKind::WrongType,
        "expected `<kind>:<to>` first".to_string(),
    ))?;
    let kind = RelationKind::parse(kind_raw).ok_or((
        LoadErrorKind::UnknownValue,
        format!("`{kind_raw}` is owns, controls or related"),
    ))?;
    if to.is_empty() {
        return Err((
            LoadErrorKind::WrongType,
            "the relation names no party".into(),
        ));
    }
    let (mut basis, mut valid_from, mut valid_to, mut pct) = (None, None, None, None);
    for part in parts {
        let (k, v) = part.split_once('=').ok_or((
            LoadErrorKind::WrongType,
            format!("`{part}` is not `<key>=<value>`"),
        ))?;
        match k {
            "basis" => basis = Some(v.to_string()),
            "valid_from" => valid_from = Some(v.to_string()),
            "valid_to" => valid_to = Some(v.to_string()),
            "pct" => {
                let parsed = v
                    .split_once('/')
                    .and_then(|(n, d)| Some((n.parse::<u128>().ok()?, d.parse::<u128>().ok()?)))
                    .filter(|(_, d)| *d > 0);
                pct = Some(parsed.ok_or((
                    LoadErrorKind::WrongType,
                    format!("`pct={v}` is not `<num>/<den>`"),
                ))?);
            }
            other => {
                return Err((
                    LoadErrorKind::WrongType,
                    format!("unknown relation key `{other}`"),
                ));
            }
        }
    }
    let basis = basis.ok_or((
        LoadErrorKind::MissingField,
        "`basis=<code>` is required (fa party relate --basis)".to_string(),
    ))?;
    let valid_from = valid_from.ok_or((
        LoadErrorKind::MissingField,
        "`valid_from=<date>` is required (fa party relate --valid-from)".to_string(),
    ))?;
    if !reg.bases.contains(&basis) {
        return Err((
            LoadErrorKind::UnknownValue,
            format!("basis `{basis}` is not in relationship_bases.toml"),
        ));
    }
    if !is_date(&valid_from) || valid_to.as_deref().is_some_and(|d| !is_date(d)) {
        return Err((
            LoadErrorKind::WrongType,
            "`valid_from` and `valid_to` are YYYY-MM-DD dates".into(),
        ));
    }
    Ok(Relation {
        kind,
        to: to.to_string(),
        basis,
        valid_from,
        valid_to,
        pct,
    })
}

/// The cross-row checks of one book.
struct Check<'a, 'e> {
    view: &'a CaseView<'a>,
    reg: &'a Registries,
    book: &'a BookVariant,
    path: &'a str,
    text: &'a str,
    errs: &'e mut Vec<LoadError>,
}

impl<'a> Check<'a, '_> {
    fn push(
        &mut self,
        line: Option<usize>,
        row: Option<&str>,
        kind: LoadErrorKind,
        detail: String,
    ) {
        self.errs.push(LoadError {
            file: self.path.to_string(),
            line,
            kind,
            row: row.map(str::to_string),
            detail,
        });
    }

    fn key_line(&self, array: &str, index: usize, key: &str) -> Option<usize> {
        row_key_line(self.text, array, index, key)
    }

    fn fact(&self, id: &str) -> Option<&'a Fact> {
        self.view.facts.iter().find(|f| f.id == id)
    }

    fn is_source(&self, id: &str) -> bool {
        self.view.sources.iter().any(|s| s.id == id)
    }

    fn is_role(&self, label: &str) -> bool {
        self.view.roles.roles.iter().any(|r| r.label == label)
    }

    fn principal(&self, label: &str) -> bool {
        self.book.principals.iter().any(|p| p.label == label)
    }

    fn period(&self, code: &str) -> bool {
        self.book.periods.iter().any(|p| p.code == code)
    }

    fn account(&self, code: &str) -> Option<&'a AccountDef> {
        self.book.accounts.iter().find(|a| a.code == code)
    }

    fn document(&self, id: &str) -> Option<&'a DocumentDef> {
        self.book.documents.iter().find(|d| d.id == id)
    }

    fn intent(&self, id: &str) -> Option<&'a IntentDef> {
        self.book.intents.iter().find(|i| i.id == id)
    }

    fn party(&self, id: &str) -> bool {
        self.book.parties.iter().any(|p| p.id == id)
    }

    fn entity(&self, code: &str) -> bool {
        self.book.book.entity_codes().contains(&code)
    }

    fn run(mut self) {
        self.periods();
        self.principals();
        self.accounts();
        self.parties();
        self.documents();
        self.intents();
        self.ids();
        self.legs();
        self.cases();
        self.branch_classes_and_defaults();
        self.ledger_maps();
        self.events();
        self.migration_imports();
        self.steps();
        if self
            .view
            .facts
            .iter()
            .any(|f| f.id == "negate" && matches!(f.provenance, Provenance::Derived(_)))
        {
            self.push(
                None,
                Some("negate"),
                LoadErrorKind::BadId,
                "no derived fact may take the id `negate` (it names the case Δ rule)".into(),
            );
        }
    }

    fn periods(&mut self) {
        // `fa book create --opening-date` admits only the first day of a
        // Normal period of the book's calendar (`BookSpec::validate`,
        // crates/fa-journal/src/genesis.rs).
        let opening = self.book.book.opening_date.as_str();
        if is_date(opening)
            && !self
                .book
                .periods
                .iter()
                .any(|p| p.kind == "Normal" && p.start == opening)
        {
            let line = self
                .text
                .lines()
                .position(|l| l.trim_start().starts_with("opening_date"))
                .map(|n| n + 1);
            self.push(
                line,
                None,
                LoadErrorKind::UnknownPeriod,
                format!(
                    "`opening_date = \"{opening}\"` is not the first day of a Normal [[period]]; `fa book create --opening-date` admits no other day"
                ),
            );
        }
        let mut seen = BTreeSet::new();
        for p in &self.book.periods {
            if !seen.insert(p.code.as_str()) {
                self.push(
                    p.line,
                    Some(&p.code),
                    LoadErrorKind::DuplicateLabel,
                    format!(
                        "period label `{}` is declared twice (it keys the runner's label → code map)",
                        p.code
                    ),
                );
            }
        }
    }

    fn principals(&mut self) {
        let mut seen = BTreeSet::new();
        for p in &self.book.principals {
            if !seen.insert(p.label.as_str()) {
                self.push(
                    p.line,
                    Some(&p.label),
                    LoadErrorKind::DuplicateLabel,
                    format!("principal `{}` is declared twice", p.label),
                );
            }
            if !self.is_role(&p.label) {
                self.push(
                    p.line,
                    Some(&p.label),
                    LoadErrorKind::DanglingKey,
                    format!("principal `{}` is not a roles.toml label", p.label),
                );
            }
            if !self.reg.profiles.contains(&p.profile) {
                self.push(
                    p.line,
                    Some(&p.label),
                    LoadErrorKind::UnknownValue,
                    format!("`profile = \"{}\"` is not a capability profile", p.profile),
                );
            }
            for op in &p.grants {
                if !self.reg.ops.contains(op) {
                    self.push(
                        p.line,
                        Some(&p.label),
                        LoadErrorKind::UnknownValue,
                        format!("grant `{op}` is not an op of capability_caveats.toml"),
                    );
                }
            }
        }
    }

    fn accounts(&mut self) {
        let mut seen = BTreeSet::new();
        for a in &self.book.accounts {
            if !seen.insert(a.code.as_str()) {
                self.push(
                    a.line,
                    Some(&a.code),
                    LoadErrorKind::DuplicateId,
                    format!("account `{}` is declared twice", a.code),
                );
            }
            if self.fact(&a.name_fact).is_none() {
                self.push(
                    a.line,
                    Some(&a.code),
                    LoadErrorKind::DanglingKey,
                    format!("`name_fact = \"{}\"` names no fact", a.name_fact),
                );
            }
            if !self.reg.account_types.contains(&a.account_type) {
                self.push(
                    a.line,
                    Some(&a.code),
                    LoadErrorKind::UnknownValue,
                    format!("`type = \"{}\"` is not an account type", a.account_type),
                );
            }
            if let Some(role) = a.role.as_deref().filter(|r| !r.is_empty()) {
                match self.reg.account_roles.iter().find(|r| r.name == role) {
                    None => self.push(
                        a.line,
                        Some(&a.code),
                        LoadErrorKind::UnknownValue,
                        format!("`role = \"{role}\"` is not an account role"),
                    ),
                    Some(r) if !r.admits(&a.account_type) => self.push(
                        a.line,
                        Some(&a.code),
                        LoadErrorKind::UnknownValue,
                        format!(
                            "role `{role}` does not admit account type `{}` (fa chart would refuse it)",
                            a.account_type
                        ),
                    ),
                    Some(_) => {}
                }
            }
        }
    }

    fn parties(&mut self) {
        let mut seen = BTreeSet::new();
        let entities: Vec<String> = self
            .book
            .book
            .entity_codes()
            .into_iter()
            .map(str::to_string)
            .collect();
        for p in &self.book.parties {
            if !seen.insert(p.id.as_str()) {
                self.push(
                    p.line,
                    Some(&p.id),
                    LoadErrorKind::DuplicateId,
                    format!("party `{}` is declared twice", p.id),
                );
            }
            if entities.contains(&p.id) {
                self.push(
                    p.line,
                    Some(&p.id),
                    LoadErrorKind::DuplicateLabel,
                    format!(
                        "party id `{}` equals a `[book] entities` code (fa party relate resolves a party first)",
                        p.id
                    ),
                );
            }
            let sourced = self
                .fact(&p.label)
                .is_some_and(|f| matches!(f.provenance, Provenance::Sourced(_)));
            if !self.is_role(&p.label) && !sourced {
                self.push(
                    p.line,
                    Some(&p.id),
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`label = \"{}\"` is neither a roles.toml label nor a sourced fact",
                        p.label
                    ),
                );
            }
            for rel in &p.relations {
                if !self.party(&rel.to) && !entities.contains(&rel.to) {
                    self.push(
                        p.line,
                        Some(&p.id),
                        LoadErrorKind::DanglingKey,
                        format!("relation names `{}`, neither a party nor an entity", rel.to),
                    );
                }
            }
        }
    }

    fn documents(&mut self) {
        let mut seen = BTreeSet::new();
        let mut legacy = 0;
        for d in &self.book.documents {
            if !seen.insert(d.id.as_str()) {
                self.push(
                    d.line,
                    Some(&d.id),
                    LoadErrorKind::DuplicateId,
                    format!("document `{}` is declared twice", d.id),
                );
            }
            if !self.reg.grades.contains(&d.grade) {
                self.push(
                    d.line,
                    Some(&d.id),
                    LoadErrorKind::UnknownValue,
                    format!("`grade = \"{}\"` is not an evidence grade", d.grade),
                );
            }
            if let Some(by) = d.reviewed_by.as_deref().filter(|b| !b.is_empty())
                && !self.principal(by)
            {
                self.push(
                    d.line,
                    Some(&d.id),
                    LoadErrorKind::DanglingKey,
                    format!("`reviewed_by = \"{by}\"` is not a `[[principal]]`"),
                );
            }
            let stub = d.stub_of.as_str();
            let resolved = if stub == "legacy_tb" {
                legacy += 1;
                if self.book.kind != VariantKind::Migration || legacy > 1 {
                    self.push(
                        d.line,
                        Some(&d.id),
                        LoadErrorKind::UnknownValue,
                        "`stub_of = \"legacy_tb\"` belongs to a migration stem, at most once"
                            .into(),
                    );
                }
                true
            } else if let Some(f) = stub.strip_prefix("placeholder:") {
                self.fact(f).is_some()
            } else if let Some(v) = stub.strip_prefix("filler:") {
                !v.is_empty()
            } else if let Some(f) = stub.strip_prefix("rows:") {
                self.fact(f)
                    .and_then(Fact::sourced)
                    .is_some_and(|s| s.rows_file.is_some())
            } else {
                self.is_source(stub) || self.fact(stub).is_some()
            };
            if !resolved {
                self.push(
                    d.line,
                    Some(&d.id),
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`stub_of = \"{stub}\"` is not a source id, a fact id, placeholder:<fact>, filler:<variant>, rows:<rows fact> or legacy_tb"
                    ),
                );
            }
        }
    }

    fn intents(&mut self) {
        let mut seen = BTreeSet::new();
        let max_key = self.reg.max_key_bytes.saturating_sub(CELL_KEY_SUFFIX_BYTES);
        for (i, it) in self.book.intents.iter().enumerate() {
            let row = Some(it.id.as_str());
            if !seen.insert(it.id.as_str()) {
                self.push(
                    it.line,
                    row,
                    LoadErrorKind::DuplicateId,
                    format!("intent `{}` is declared twice", it.id),
                );
            }
            let fact_ok = it.fact == "synthetic"
                || it
                    .fact
                    .strip_prefix("derived:")
                    .is_some_and(|r| !r.is_empty())
                || self.fact(&it.fact).is_some();
            if !fact_ok {
                self.push(
                    self.key_line("intent", i, "fact"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`fact = \"{}\"` is not a fact id, derived:<rule> or synthetic",
                        it.fact
                    ),
                );
            }
            let supersession = self.reg.supersession.get(&it.class).cloned();
            match &supersession {
                None => self.push(
                    self.key_line("intent", i, "class"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`class = \"{}\"` is not a posting class of entry_classes.toml",
                        it.class
                    ),
                ),
                Some(sup) if TargetKind::parse(sup).is_some() => {
                    if it.target.as_deref().is_none_or(str::is_empty)
                        || it.target_kind.as_deref().is_none_or(str::is_empty)
                    {
                        self.push(
                            it.line,
                            row,
                            LoadErrorKind::TargetRequired,
                            format!(
                                "a {} intent {sup} a target: `target` and `target_kind` are required",
                                it.class
                            ),
                        );
                    } else if it.target_kind.as_deref() != Some(sup.as_str()) {
                        self.push(
                            self.key_line("intent", i, "target_kind"),
                            row,
                            LoadErrorKind::UnknownValue,
                            format!("`target_kind` of a {} intent is `{sup}`", it.class),
                        );
                    }
                }
                Some(sup) if sup == "replaces" || sup == "resolves" => self.push(
                    self.key_line("intent", i, "class"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "case books do not encode {} intents (no target kind for `{sup}`)",
                        it.class
                    ),
                ),
                Some(_) => {}
            }
            if let Some(tk) = it.target_kind.as_deref().filter(|t| !t.is_empty())
                && TargetKind::parse(tk).is_none()
            {
                self.push(
                    self.key_line("intent", i, "target_kind"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("`target_kind = \"{tk}\"` is outside its closed set"),
                );
            }
            if let Some(t) = it.target.as_deref().filter(|t| !t.is_empty())
                && self.intent(t).is_none()
            {
                self.push(
                    self.key_line("intent", i, "target"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`target = \"{t}\"` names no intent"),
                );
            }
            if !self.principal(&it.principal) {
                self.push(
                    self.key_line("intent", i, "principal"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`principal = \"{}\"` is not a `[[principal]]`",
                        it.principal
                    ),
                );
            }
            if is_date(&it.effective_date)
                && !self
                    .book
                    .periods
                    .iter()
                    .any(|p| p.contains(&it.effective_date))
            {
                self.push(
                    self.key_line("intent", i, "effective_date"),
                    row,
                    LoadErrorKind::UnknownPeriod,
                    format!(
                        "`effective_date = \"{}\"` falls in no declared period",
                        it.effective_date
                    ),
                );
            }
            if let Some(ev) = it.evidence.as_deref().filter(|e| !e.is_empty()) {
                let ok = match ev.strip_prefix("manual_assertion:") {
                    Some(code) => self
                        .reg
                        .reasons
                        .contains(&("manual_assertion".to_string(), code.to_string())),
                    None => self.document(ev).is_some(),
                };
                if !ok {
                    self.push(
                        self.key_line("intent", i, "evidence"),
                        row,
                        LoadErrorKind::DanglingKey,
                        format!(
                            "`evidence = \"{ev}\"` is neither a `[[document]]` nor manual_assertion:<a registered manual_assertion reason>"
                        ),
                    );
                }
            }
            if let Some(reason) = it.reason.as_deref().filter(|r| !r.is_empty())
                && !self
                    .reg
                    .reasons
                    .contains(&("supersession".to_string(), reason.to_string()))
            {
                self.push(
                    self.key_line("intent", i, "reason"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`reason = \"{reason}\"` is not a supersession reason"),
                );
            }
            if let Some(key) = &it.idempotency_key
                && key.len() > max_key
            {
                self.push(
                    self.key_line("intent", i, "idempotency_key"),
                    row,
                    LoadErrorKind::TooLong,
                    format!(
                        "the idempotency key is {} bytes; an authored key fits in {max_key} so A7c's per-cell suffix stays inside max_idempotency_key_bytes",
                        key.len()
                    ),
                );
            }
            if let Some(memo) = &it.memo
                && memo.len() > self.reg.max_memo_bytes
            {
                self.push(
                    self.key_line("intent", i, "memo"),
                    row,
                    LoadErrorKind::TooLong,
                    format!(
                        "the memo is {} bytes; max_memo_bytes is {}",
                        memo.len(),
                        self.reg.max_memo_bytes
                    ),
                );
            }
            for (field, label) in [
                ("source_entered_by", &it.source_entered_by),
                ("source_approved_by", &it.source_approved_by),
            ] {
                if let Some(l) = label
                    && !self.is_role(l)
                {
                    self.push(
                        self.key_line("intent", i, field),
                        row,
                        LoadErrorKind::DanglingKey,
                        format!("`{field} = \"{l}\"` is not a roles.toml label"),
                    );
                }
            }
            self.allocation(i, it);
        }
    }

    fn allocation(&mut self, i: usize, it: &IntentDef) {
        let row = Some(it.id.as_str());
        let any = it.allocation_law.is_some()
            || it.allocation_total.is_some()
            || it.allocation_targets.is_some()
            || it.allocation_source.is_some()
            || it.allocation_source_side.is_some();
        if !any {
            return;
        }
        match it.allocation_law.as_deref() {
            None => self.push(
                it.line,
                row,
                LoadErrorKind::MissingField,
                "an allocation intent names its `allocation_law`".into(),
            ),
            Some(law) if !self.reg.allocation_laws.contains(law) => self.push(
                self.key_line("intent", i, "allocation_law"),
                row,
                LoadErrorKind::UnknownValue,
                format!("`allocation_law = \"{law}\"` is not in allocation_laws.toml"),
            ),
            Some(_) => {}
        }
        match it.allocation_source.as_deref() {
            None => self.push(
                it.line,
                row,
                LoadErrorKind::MissingField,
                "an allocation intent names its `allocation_source` account".into(),
            ),
            Some(src) if self.account(src).is_none() => self.push(
                self.key_line("intent", i, "allocation_source"),
                row,
                LoadErrorKind::DanglingKey,
                format!("`allocation_source = \"{src}\"` is not an `[[account]]`"),
            ),
            Some(_) => {}
        }
        if let Some(total) = &it.allocation_total {
            let scale = self
                .reg
                .unit_scales
                .get(&self.book.book.base_unit)
                .copied()
                .unwrap_or(0);
            if let Err(e) = parse_amount(total, scale) {
                self.push(
                    self.key_line("intent", i, "allocation_total"),
                    row,
                    LoadErrorKind::WrongType,
                    format!("`allocation_total`: {e}"),
                );
            }
            match it.allocation_source_side.as_deref() {
                None => self.push(
                    it.line,
                    row,
                    LoadErrorKind::MissingField,
                    "an explicit `allocation_total` needs `allocation_source_side` (debit or credit)"
                        .into(),
                ),
                Some(side) if AllocationSide::parse(side).is_none() => self.push(
                    self.key_line("intent", i, "allocation_source_side"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("`allocation_source_side = \"{side}\"` is debit or credit"),
                ),
                Some(_) => {}
            }
        }
        let targets = it.allocation_targets.as_deref().unwrap_or(&[]);
        if targets.is_empty() {
            self.push(
                it.line,
                row,
                LoadErrorKind::MissingField,
                "an allocation intent lists its `allocation_targets`".into(),
            );
        }
        for t in targets {
            if self.account(t).is_none() {
                self.push(
                    self.key_line("intent", i, "allocation_targets"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("allocation target `{t}` is not an `[[account]]`"),
                );
            }
        }
    }

    /// Plan §3.2b: a documented entry's intent is named after its fact, a
    /// case Δ after its target.
    fn ids(&mut self) {
        let mut deltas: BTreeMap<&str, Vec<&IntentDef>> = BTreeMap::new();
        for it in &self.book.intents {
            if it.is_delta()
                && let Some(t) = it.target.as_deref()
            {
                deltas.entry(t).or_default().push(it);
            }
        }
        for (target, list) in &deltas {
            for (n, it) in list.iter().enumerate() {
                let want = if list.len() == 1 {
                    format!("delta-{target}")
                } else {
                    format!("delta-{target}-{}", n + 1)
                };
                if it.id != want {
                    self.push(
                        it.line,
                        Some(&it.id),
                        LoadErrorKind::BadId,
                        format!(
                            "a case Δ of `{target}` is `{want}` ({} Δ(s) of that target, numbered in file order)",
                            list.len()
                        ),
                    );
                }
            }
        }
        for it in &self.book.intents {
            if it.is_delta() {
                continue;
            }
            let documented = self.fact(&it.fact).is_some_and(|f| {
                matches!(
                    f.provenance,
                    Provenance::Sourced(_) | Provenance::Interpretation(_)
                )
            });
            if !documented {
                continue;
            }
            let ok = it.id == it.fact
                || it
                    .id
                    .strip_prefix(it.fact.as_str())
                    .is_some_and(|s| s.len() == 1 && s.bytes().all(|b| b.is_ascii_lowercase()));
            if !ok {
                self.push(
                    it.line,
                    Some(&it.id),
                    LoadErrorKind::BadId,
                    format!(
                        "the intent of documented entry `{}` is `{}` (or `{}` plus one letter, F6a/F6b)",
                        it.fact, it.fact, it.fact
                    ),
                );
            }
        }
    }

    fn legs(&mut self) {
        let mut by_intent: BTreeMap<&str, Vec<(usize, &LegDef)>> = BTreeMap::new();
        for (i, leg) in self.book.legs.iter().enumerate() {
            by_intent
                .entry(leg.intent.as_str())
                .or_default()
                .push((i, leg));
            let n = i + 1;
            if self.intent(&leg.intent).is_none() {
                self.push(
                    self.key_line("leg", i, "intent"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n} names intent {}", leg.intent),
                );
            }
            if self.account(&leg.account).is_none() {
                self.push(
                    self.key_line("leg", i, "account"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n} names account {}", leg.account),
                );
            }
            if let Some(p) = leg.party.as_deref().filter(|p| !p.is_empty())
                && !self.party(p)
            {
                self.push(
                    self.key_line("leg", i, "party"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n} names party {p}, which is not a `[[party]]`"),
                );
            }
            if let Some(e) = leg.entity.as_deref().filter(|e| !e.is_empty())
                && !self.entity(e)
            {
                self.push(
                    self.key_line("leg", i, "entity"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n} names entity {e}, which is not a `[book] entities` code"),
                );
            }
            match self.reg.unit_scales.get(&leg.unit).copied() {
                None => self.push(
                    self.key_line("leg", i, "unit"),
                    None,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "leg {n}: `unit = \"{}\"` is not a registered unit",
                        leg.unit
                    ),
                ),
                Some(scale) => {
                    if let Err(e) = parse_amount(&leg.amount_literal, scale) {
                        self.push(
                            self.key_line("leg", i, "amount_literal"),
                            None,
                            LoadErrorKind::WrongType,
                            format!("leg {n}: {e}"),
                        );
                    } else if leg.amount_literal.starts_with('-') {
                        self.push(
                            self.key_line("leg", i, "amount_literal"),
                            None,
                            LoadErrorKind::WrongType,
                            format!("leg {n}: a leg carries no sign; `side` is its direction"),
                        );
                    }
                }
            }
            self.amount_rule(i, leg);
        }
        for it in &self.book.intents {
            let legs = by_intent.get(it.id.as_str()).cloned().unwrap_or_default();
            if legs.is_empty() {
                if !it.is_allocation() {
                    self.push(
                        it.line,
                        Some(&it.id),
                        LoadErrorKind::MissingField,
                        format!("intent {} has no `[[leg]]` rows", it.id),
                    );
                }
                continue;
            }
            let mut ordinals: Vec<i128> = legs.iter().map(|(_, l)| l.ordinal).collect();
            ordinals.sort_unstable();
            if ordinals.iter().zip(0..).any(|(o, want)| *o != want) {
                let (i, _) = legs[0];
                self.push(
                    self.key_line("leg", i, "ordinal"),
                    None,
                    LoadErrorKind::WrongType,
                    format!(
                        "intent {}'s leg ordinals are {ordinals:?}; they run 0, 1, … n − 1 (the kernel's cited-leg index)",
                        it.id
                    ),
                );
            }
            self.balance(it, &legs);
        }
    }

    fn amount_rule(&mut self, i: usize, leg: &LegDef) {
        let n = i + 1;
        let rule = leg.amount_rule.as_str();
        let line = self.key_line("leg", i, "amount_rule");
        if rule == "synthetic" {
            return;
        }
        if let Some(rest) = rule.strip_prefix("value:") {
            let ok = rest.split_once('#').is_some_and(|(fact, ord)| {
                ord.parse::<i128>().is_ok_and(|o| {
                    self.view
                        .values
                        .iter()
                        .any(|v| v.fact == fact && v.ordinal == o)
                })
            });
            if !ok {
                self.push(
                    line,
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n}: `{rule}` names no `[[value]]` row (value:<fact>#<1-based ordinal>)"),
                );
            }
            return;
        }
        if let Some(class) = rule.strip_prefix("branch:") {
            if !self.book.branch_classes.iter().any(|b| b.id == class) {
                self.push(
                    line,
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("leg {n}: `{rule}` names no `[[branch_class]]`"),
                );
            }
            return;
        }
        if let Some(name) = rule.strip_prefix("derived:") {
            if name == "negate" {
                self.negate(i, leg);
                return;
            }
            let derived = self
                .fact(name)
                .is_some_and(|f| matches!(f.provenance, Provenance::Derived(_)));
            if !derived {
                self.push(
                    line,
                    None,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "leg {n}: `{rule}` names no derived fact (a computed amount names its derived fact; a bare rule name has no inputs to recompute)"
                    ),
                );
            }
            return;
        }
        self.push(
            line,
            None,
            LoadErrorKind::WrongType,
            format!(
                "leg {n}: `amount_rule = \"{rule}\"` is value:<fact>#<n>, derived:<fact>, derived:negate, branch:<class> or synthetic"
            ),
        );
    }

    /// `derived:negate`: on a case Δ only, the target's leg with the same
    /// ordinal, same account and unit, opposite side. The amount itself is
    /// K-DERIVE's (A3a).
    fn negate(&mut self, i: usize, leg: &LegDef) {
        let n = i + 1;
        let line = self.key_line("leg", i, "amount_rule");
        let Some(it) = self.intent(&leg.intent) else {
            return;
        };
        if !it.is_delta() {
            self.push(
                line,
                None,
                LoadErrorKind::UnknownValue,
                format!("leg {n}: derived:negate belongs to a case Δ (restates or revises)"),
            );
            return;
        }
        let Some(target) = it.target.as_deref() else {
            return;
        };
        let mirrored = self.book.legs.iter().any(|t| {
            t.intent == target
                && t.ordinal == leg.ordinal
                && t.account == leg.account
                && t.unit == leg.unit
                && t.side != leg.side
        });
        if !mirrored {
            self.push(
                line,
                None,
                LoadErrorKind::DanglingKey,
                format!(
                    "leg {n}: derived:negate needs {target}'s leg {} on account {} in {} on the opposite side",
                    leg.ordinal, leg.account, leg.unit
                ),
            );
        }
    }

    fn balance(&mut self, it: &IntentDef, legs: &[(usize, &LegDef)]) {
        let mut totals = UnitTotals::default();
        for (_, leg) in legs {
            let Some(scale) = self.reg.unit_scales.get(&leg.unit).copied() else {
                return;
            };
            let Ok(amount) = parse_amount(&leg.amount_literal, scale) else {
                return;
            };
            let Some(side) = Side::parse(&leg.side) else {
                return;
            };
            if let Err(e) = totals.add(&leg.unit, side == Side::Dr, amount) {
                self.push(
                    it.line,
                    Some(&it.id),
                    LoadErrorKind::WrongType,
                    format!("intent {} {}: {e}", it.id, leg.unit),
                );
                return;
            }
        }
        for (unit, dr, cr) in totals.unbalanced() {
            let scale = self.reg.unit_scales.get(unit).copied().unwrap_or(0);
            let gap = dr.checked_sub(cr).map_or_else(
                || "beyond i128".to_string(),
                |g| format_amount(g.abs(), scale),
            );
            self.push(
                it.line,
                Some(&it.id),
                LoadErrorKind::Unbalanced,
                format!(
                    "intent {} {unit} Dr {} Cr {} gap {gap}",
                    it.id,
                    format_amount(dr, scale),
                    format_amount(cr, scale)
                ),
            );
        }
    }

    fn cases(&mut self) {
        let mut seen = BTreeSet::new();
        for c in &self.book.cases {
            let row = Some(c.id.as_str());
            if !seen.insert(c.id.as_str()) {
                self.push(
                    c.line,
                    row,
                    LoadErrorKind::DuplicateId,
                    format!("case `{}` is declared twice", c.id),
                );
            }
            for p in &c.periods {
                if !self.period(p) {
                    self.push(
                        c.line,
                        row,
                        LoadErrorKind::UnknownPeriod,
                        format!(
                            "case {} affects `{p}`, which is not a declared period",
                            c.id
                        ),
                    );
                }
            }
            let determined = if c.determined_on == "default" {
                self.book
                    .defaults
                    .iter()
                    .any(|d| d.attribute == "case_determination_date")
            } else {
                self.fact(&c.determined_on).is_some()
            };
            if !determined {
                self.push(
                    c.line,
                    row,
                    LoadErrorKind::DanglingKey,
                    format!(
                        "`determined_on = \"{}\"` is neither a fact id nor `default` with a case_determination_date `[[default]]`",
                        c.determined_on
                    ),
                );
            }
            for (field, doc) in [("authority", &c.authority), ("disclosure", &c.disclosure)] {
                if self.document(doc).is_none() {
                    self.push(
                        c.line,
                        row,
                        LoadErrorKind::DanglingKey,
                        format!("`{field} = \"{doc}\"` is not a `[[document]]`"),
                    );
                }
            }
            let distinct: BTreeSet<&String> = c.approvers.iter().collect();
            if c.approvers.len() != 2 || distinct.len() != 2 {
                self.push(
                    c.line,
                    row,
                    LoadErrorKind::WrongType,
                    "a case names two distinct `approvers`".into(),
                );
            }
            for label in c.approvers.iter().chain([&c.poster]) {
                if !self.principal(label) {
                    self.push(
                        c.line,
                        row,
                        LoadErrorKind::DanglingKey,
                        format!(
                            "case {} names `{label}`, which is not a `[[principal]]`",
                            c.id
                        ),
                    );
                }
            }
            if c.approvers.contains(&c.poster) {
                self.push(
                    c.line,
                    row,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "the poster `{}` is one of the case's approvers (fa case post refuses an approver)",
                        c.poster
                    ),
                );
            }
        }
    }

    fn branch_classes_and_defaults(&mut self) {
        let mut seen = BTreeSet::new();
        let rules = super::branch::rules();
        for b in &self.book.branch_classes {
            if !seen.insert(b.id.as_str()) {
                self.push(
                    b.line,
                    Some(&b.id),
                    LoadErrorKind::DuplicateId,
                    format!("branch class `{}` is declared twice", b.id),
                );
            }
            // Its rule is a registered class rule of the same attribute,
            // whose classes admit every value (A5a).
            let problem = match &rules {
                // An empty list is refused where the row is read.
                Ok(_) if b.values.is_empty() => None,
                Ok(rules) => super::branch::class_problem(rules, b),
                Err(errs) => errs
                    .first()
                    .map(|e| format!("{}: {e}", super::branch::FILE)),
            };
            if let Some(detail) = problem {
                self.push(b.line, Some(&b.id), LoadErrorKind::UnknownValue, detail);
            }
        }
        for d in &self.book.defaults {
            let ok = BranchAttribute::parse(&d.attribute).is_some()
                || d.attribute == "reason"
                || (self.book.kind == VariantKind::Ledger
                    && (d.attribute == "sign" || d.attribute == "period_grain"));
            if !ok {
                self.push(
                    d.line,
                    None,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`[[default]] attribute = \"{}\"` is a §2.6 attribute, `reason`, or (on a ledger stem) `sign` or `period_grain`",
                        d.attribute
                    ),
                );
            }
        }
    }

    fn ledger_maps(&mut self) {
        for (i, m) in self.book.ledger_maps.iter().enumerate() {
            if self.book.kind != VariantKind::Ledger {
                self.push(
                    m.line,
                    None,
                    LoadErrorKind::UnknownField,
                    format!(
                        "`[[ledger_map]]` belongs to a ledger stem, not `{}`",
                        self.book.stem
                    ),
                );
            }
            if self.fact(&m.source).is_none() {
                self.push(
                    self.key_line("ledger_map", i, "source"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("`source = \"{}\"` names no fact", m.source),
                );
            }
            for (field, code) in [
                ("book_account", &m.book_account),
                ("cash_account", &m.cash_account),
                ("transfer_account", &m.transfer_account),
            ] {
                if self.account(code).is_none() {
                    self.push(
                        self.key_line("ledger_map", i, field),
                        None,
                        LoadErrorKind::DanglingKey,
                        format!("`{field} = \"{code}\"` is not an `[[account]]`"),
                    );
                }
            }
            if let Some(role) = self
                .account(&m.transfer_account)
                .and_then(|a| a.role.clone())
                .filter(|r| r == "cash" || r == "investor_capital")
            {
                self.push(
                    self.key_line("ledger_map", i, "transfer_account"),
                    None,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "the transfer account holds the `{role}` role; a transfer account holds neither cash nor investor_capital"
                    ),
                );
            }
            if !self.party(&m.party) {
                self.push(
                    self.key_line("ledger_map", i, "party"),
                    None,
                    LoadErrorKind::DanglingKey,
                    format!("`party = \"{}\"` is not a `[[party]]`", m.party),
                );
            }
        }
    }

    fn events(&mut self) {
        let mut seen = BTreeSet::new();
        for (i, e) in self.book.events.iter().enumerate() {
            let row = Some(e.id.as_str());
            if !seen.insert(e.id.as_str()) {
                self.push(
                    e.line,
                    row,
                    LoadErrorKind::DuplicateId,
                    format!("event `{}` is declared twice", e.id),
                );
            }
            if e.evidence.is_empty() {
                self.push(
                    e.line,
                    row,
                    LoadErrorKind::MissingField,
                    "every recorded Event requires at least one evidence citation".into(),
                );
            }
            for d in &e.evidence {
                if self.document(d).is_none() {
                    self.push(
                        self.key_line("event", i, "evidence"),
                        row,
                        LoadErrorKind::DanglingKey,
                        format!("event evidence `{d}` is not a `[[document]]`"),
                    );
                }
            }
            for p in e.participants.iter().flatten() {
                if !self.party(p) && !self.entity(p) {
                    self.push(
                        self.key_line("event", i, "participants"),
                        row,
                        LoadErrorKind::DanglingKey,
                        format!("participant `{p}` is neither a party nor an entity"),
                    );
                }
            }
            let resource = [
                &e.resource_label,
                &e.resource_amount_literal,
                &e.resource_amount_rule,
                &e.resource_unit,
            ];
            let present = resource.iter().filter(|f| f.is_some()).count();
            if present != 0 && present != resource.len() {
                self.push(
                    e.line,
                    row,
                    LoadErrorKind::MissingField,
                    "an event's resource names its label, amount literal, amount rule and unit together"
                        .into(),
                );
            }
            if let (Some(unit), Some(lit)) = (&e.resource_unit, &e.resource_amount_literal) {
                match self.reg.unit_scales.get(unit) {
                    None => self.push(
                        self.key_line("event", i, "resource_unit"),
                        row,
                        LoadErrorKind::UnknownValue,
                        format!("`resource_unit = \"{unit}\"` is not a registered unit"),
                    ),
                    Some(scale) => {
                        if let Err(err) = parse_amount(lit, *scale) {
                            self.push(
                                self.key_line("event", i, "resource_amount_literal"),
                                row,
                                LoadErrorKind::WrongType,
                                format!("{err}"),
                            );
                        }
                    }
                }
            }
        }
    }

    fn migration_imports(&mut self) {
        let opens: BTreeMap<i128, &str> = self
            .book
            .steps
            .iter()
            .filter(|s| s.step_kind() == Some(StepKind::MigrateOpen))
            .map(|s| (s.seq, s.reference.as_str()))
            .collect();
        let mut seen = BTreeSet::new();
        for (i, m) in self.book.migration_imports.iter().enumerate() {
            let row = Some(m.id.as_str());
            if !seen.insert(m.id.as_str()) {
                self.push(
                    m.line,
                    row,
                    LoadErrorKind::DuplicateId,
                    format!("import `{}` is declared twice", m.id),
                );
            }
            if !opens.contains_key(&m.run) {
                self.push(
                    self.key_line("migration_import", i, "run"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`run = {}` is not the seq of a migrate_open step", m.run),
                );
            }
            if self.document(&m.source).is_none() {
                self.push(
                    self.key_line("migration_import", i, "source"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`source = \"{}\"` is not a `[[document]]`", m.source),
                );
            } else if opens.values().any(|tb| *tb == m.source) {
                self.push(
                    self.key_line("migration_import", i, "source"),
                    row,
                    LoadErrorKind::UnknownValue,
                    "an import's source document differs from every trial-balance document".into(),
                );
            }
            let format = ImportFormat::parse(&m.format);
            if format.is_none() {
                self.push(
                    self.key_line("migration_import", i, "format"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!(
                        "`format = \"{}\"` is not a `fa migrate import` format",
                        m.format
                    ),
                );
            }
            if format == Some(ImportFormat::Csv) && m.column_map.is_none() {
                self.push(
                    m.line,
                    row,
                    LoadErrorKind::MissingField,
                    "a generic csv import names its `column_map`".into(),
                );
            }
            if let Some(u) = &m.default_unit
                && !self.reg.unit_scales.contains_key(u)
            {
                self.push(
                    self.key_line("migration_import", i, "default_unit"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("`default_unit = \"{u}\"` is not a registered unit"),
                );
            }
            for token in &m.account_map {
                let ok = token.split_once('=').is_some_and(|(legacy, code)| {
                    !legacy.is_empty() && self.account(code).is_some()
                });
                if !ok {
                    self.push(
                        self.key_line("migration_import", i, "account_map"),
                        row,
                        LoadErrorKind::DanglingKey,
                        format!("`{token}` is not `<legacy account>=<an [[account]] code>`"),
                    );
                }
            }
            for token in m.entry_periods.iter().flatten() {
                let ok = token
                    .split_once('=')
                    .is_some_and(|(src, p)| !src.is_empty() && self.period(p));
                if !ok {
                    self.push(
                        self.key_line("migration_import", i, "entry_periods"),
                        row,
                        LoadErrorKind::UnknownPeriod,
                        format!("`{token}` is not `<source id>=<a declared period label>`"),
                    );
                }
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    fn steps(&mut self) {
        let mut last_seq: Option<i128> = None;
        let mut checkpoints: BTreeSet<&str> = BTreeSet::new();
        let mut finding_records = 0usize;
        let mut rule_proposes: BTreeSet<i128> = BTreeSet::new();
        let mut migrate_opens: BTreeSet<i128> = BTreeSet::new();
        let mut import_chunks: BTreeMap<&str, Option<u64>> = BTreeMap::new();
        let scenarios: BTreeSet<&str> = self
            .book
            .intents
            .iter()
            .filter_map(|i| i.scenario.as_deref().filter(|s| !s.is_empty()))
            .collect();
        for (i, s) in self.book.steps.iter().enumerate() {
            let line = s.line;
            let ref_line = self.key_line("step", i, "ref");
            let label = format!("step {}", s.seq);
            let row = Some(label.as_str());
            if last_seq.is_some_and(|l| s.seq <= l) {
                self.push(
                    self.key_line("step", i, "seq"),
                    row,
                    LoadErrorKind::WrongType,
                    "`seq` values are unique and strictly increasing in file order (the steps are the documented history)".into(),
                );
            }
            last_seq = Some(s.seq);
            let Some(kind) = s.step_kind() else {
                continue;
            };
            let r = s.reference.as_str();
            // Fields that belong to a few kinds only.
            let only = |field: &str, present: bool, kinds: &[StepKind]| -> Option<String> {
                (present && !kinds.contains(&kind)).then(|| {
                    format!(
                        "`{field}` belongs to {} steps, not `{}`",
                        kind_list(kinds),
                        s.kind
                    )
                })
            };
            for (field, present, kinds) in [
                (
                    "known_at",
                    s.known_at.is_some(),
                    &[StepKind::FindingRecord][..],
                ),
                (
                    "params",
                    s.params.is_some(),
                    &[StepKind::FindingRecord, StepKind::RuleBacktest][..],
                ),
                (
                    "evidence",
                    s.evidence.is_some(),
                    &[StepKind::AssertBalance][..],
                ),
                (
                    "asserts",
                    s.asserts.is_some(),
                    &[StepKind::AssertBalance][..],
                ),
                ("document", s.document.is_some(), &[StepKind::Issue][..]),
                (
                    "approvers",
                    s.approvers.is_some(),
                    &[
                        StepKind::PeriodLock,
                        StepKind::Issue,
                        StepKind::MigrateStage,
                        StepKind::MigrateFinalize,
                        StepKind::MigrateImport,
                    ][..],
                ),
            ] {
                if let Some(detail) = only(field, present, kinds) {
                    self.push(
                        self.key_line("step", i, field),
                        row,
                        LoadErrorKind::UnknownField,
                        detail,
                    );
                }
            }
            if let Some(k) = s.known_at.as_deref()
                && KnownAt::parse(k).is_none()
            {
                self.push(
                    self.key_line("step", i, "known_at"),
                    row,
                    LoadErrorKind::UnknownValue,
                    format!("`known_at = \"{k}\"` is head or pre_case"),
                );
            }
            if let Some(b) = s.branch_class.as_deref().filter(|b| !b.is_empty())
                && !self.book.branch_classes.iter().any(|c| c.id == b)
            {
                self.push(
                    self.key_line("step", i, "branch_class"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("`branch_class = \"{b}\"` names no `[[branch_class]]`"),
                );
            }
            // The step's principal.
            let principal = s
                .principal
                .clone()
                .or_else(|| kind.default_principal().map(str::to_string));
            let needs_principal =
                !kind.runs_intents() && !matches!(kind, StepKind::CaseApprove | StepKind::CasePost);
            match &principal {
                None if needs_principal => self.push(
                    line,
                    row,
                    LoadErrorKind::MissingField,
                    format!("a `{}` step names the `principal` that runs it", s.kind),
                ),
                Some(p) if !self.principal(p) => self.push(
                    self.key_line("step", i, "principal"),
                    row,
                    LoadErrorKind::DanglingKey,
                    format!("principal `{p}` is not a `[[principal]]`"),
                ),
                _ => {}
            }
            // Approvers.
            let import_stage = kind == StepKind::MigrateImport && r.contains('#');
            let want_approvers = match kind {
                StepKind::PeriodLock | StepKind::Issue => Some(1..=usize::MAX),
                StepKind::MigrateStage | StepKind::MigrateFinalize => Some(2..=2),
                StepKind::MigrateImport if import_stage => Some(2..=2),
                _ => None,
            };
            if let Some(range) = want_approvers {
                let approvers = s.approvers.as_deref().unwrap_or(&[]);
                if !range.contains(&approvers.len()) {
                    self.push(
                        line,
                        row,
                        LoadErrorKind::MissingField,
                        format!(
                            "a `{}` step names {} approver(s); it names {}",
                            s.kind,
                            if *range.end() == 2 { "two" } else { "its" },
                            approvers.len()
                        ),
                    );
                }
                for a in approvers {
                    if !self.principal(a) {
                        self.push(
                            self.key_line("step", i, "approvers"),
                            row,
                            LoadErrorKind::DanglingKey,
                            format!("approver `{a}` is not a `[[principal]]`"),
                        );
                    }
                    if principal.as_deref() == Some(a.as_str()) {
                        self.push(
                            self.key_line("step", i, "approvers"),
                            row,
                            LoadErrorKind::UnknownValue,
                            format!("`{a}` approves its own `{}` step", s.kind),
                        );
                    }
                }
            }
            // Per-kind fields.
            match kind {
                StepKind::AssertBalance => {
                    match s.evidence.as_deref() {
                        None => self.push(
                            line,
                            row,
                            LoadErrorKind::MissingField,
                            "an assert_balance step names the filing stub its --evidence cites"
                                .into(),
                        ),
                        Some(d) if self.document(d).is_none() => self.push(
                            self.key_line("step", i, "evidence"),
                            row,
                            LoadErrorKind::DanglingKey,
                            format!("`evidence = \"{d}\"` is not a `[[document]]`"),
                        ),
                        Some(_) => {}
                    }
                    if let Some(f) = s.asserts.as_deref()
                        && self.fact(f).is_none()
                    {
                        self.push(
                            self.key_line("step", i, "asserts"),
                            row,
                            LoadErrorKind::DanglingKey,
                            format!("`asserts = \"{f}\"` names no fact"),
                        );
                    }
                }
                StepKind::Issue => match s.document.as_deref() {
                    None => self.push(
                        line,
                        row,
                        LoadErrorKind::MissingField,
                        "an issue step names the filing stub its issuance cites (`document`)"
                            .into(),
                    ),
                    Some(d) => {
                        let source_stub = self
                            .document(d)
                            .is_some_and(|doc| self.is_source(&doc.stub_of));
                        if !source_stub {
                            self.push(
                                self.key_line("step", i, "document"),
                                row,
                                LoadErrorKind::DanglingKey,
                                format!("`document = \"{d}\"` is not a `[[document]]` whose stub_of is a source id"),
                            );
                        }
                    }
                },
                _ => {}
            }
            if let Some(params) = &s.params {
                self.params(i, s, kind, params, &rule_proposes);
            }
            // The ref.
            let problem: Option<(LoadErrorKind, String)> = match kind {
                StepKind::Intent => self
                    .intent(r)
                    .is_none()
                    .then(|| (LoadErrorKind::DanglingKey, format!("`ref = \"{r}\"` names no intent"))),
                StepKind::Allocate => match self.intent(r) {
                    None => Some((LoadErrorKind::DanglingKey, format!("`ref = \"{r}\"` names no intent"))),
                    Some(it) if !it.is_allocation() => Some((
                        LoadErrorKind::UnknownValue,
                        format!("`ref = \"{r}\"` is not an allocation intent"),
                    )),
                    Some(_) => None,
                },
                StepKind::Batch | StepKind::MigrateStage => {
                    let ledger_account = kind == StepKind::Batch
                        && self.book.kind == VariantKind::Ledger
                        && self.book.ledger_maps.iter().any(|m| m.account == r);
                    if ledger_account {
                        None
                    } else {
                        self.range(r)
                    }
                }
                StepKind::FillerBatch => {
                    if matches!(self.book.kind, VariantKind::Statement | VariantKind::Ledger) {
                        Some((
                            LoadErrorKind::UnknownValue,
                            format!(
                                "a {} stem carries no filler (plan §3.2)",
                                self.book.kind.as_str()
                            ),
                        ))
                    } else if r.is_empty() {
                        Some((LoadErrorKind::MissingField, "a filler_batch names its filler variant".into()))
                    } else if self.book.kind == VariantKind::Migration {
                        // Migration filler is staged chunks, before finalize (A6).
                        self.book.steps[..i]
                            .iter()
                            .any(|p| p.step_kind() == Some(StepKind::MigrateFinalize))
                            .then(|| {
                                (
                                    LoadErrorKind::UnknownPeriod,
                                    format!(
                                        "filler_batch step {} comes after `migrate_finalize`; migration filler is staged before it (A6)",
                                        s.seq
                                    ),
                                )
                            })
                    } else {
                        // Filler posts while its periods are Open: after
                        // their period_open step and before their first
                        // soft-close, close or lock (A6).
                        super::filler::open_at(self.book, s.seq).is_empty().then(|| {
                            (
                                LoadErrorKind::UnknownPeriod,
                                format!(
                                    "filler_batch step {} posts while no period is Open: filler for a period comes after its period_open step and before its first soft-close, close or lock (A6)",
                                    s.seq
                                ),
                            )
                        })
                    }
                }
                StepKind::Issue => (!self.period(r))
                    .then(|| (LoadErrorKind::UnknownPeriod, format!("`ref = \"{r}\"` is not a declared period"))),
                k if k.is_period() => (!self.period(r))
                    .then(|| (LoadErrorKind::UnknownPeriod, format!("`ref = \"{r}\"` is not a declared period"))),
                k if k.is_case() => (!self.book.cases.iter().any(|c| c.id == r))
                    .then(|| (LoadErrorKind::DanglingKey, format!("`ref = \"{r}\"` names no `[[case]]`"))),
                StepKind::ScenarioFork | StepKind::ScenarioRun | StepKind::ScenarioDiff => {
                    (!scenarios.contains(r)).then(|| {
                        (
                            LoadErrorKind::DanglingKey,
                            format!("scenario `{r}` is planned into by no intent"),
                        )
                    })
                }
                StepKind::Checkpoint => (!checkpoints.insert(r)).then(|| {
                    (
                        LoadErrorKind::DuplicateLabel,
                        format!("checkpoint label `{r}` is used twice"),
                    )
                }),
                StepKind::CheckpointWitness => (!checkpoints.contains(r)).then(|| {
                    (
                        LoadErrorKind::DanglingKey,
                        format!("`ref = \"{r}\"` is no earlier checkpoint"),
                    )
                }),
                StepKind::FindingRecord => {
                    finding_records += 1;
                    self.procedure(r)
                }
                StepKind::FindingReview => r
                    .is_empty()
                    .then(|| (LoadErrorKind::MissingField, "a finding_review names its expectation".into())),
                StepKind::AssertBalance => {
                    let (exp, target) = r.split_once('#').map_or((r, None), |(e, t)| (e, Some(t)));
                    if exp.is_empty() {
                        Some((LoadErrorKind::MissingField, "an assert_balance names its expectation".into()))
                    } else {
                        target.filter(|t| self.fact(t).is_none()).map(|t| {
                            (LoadErrorKind::DanglingKey, format!("`#{t}` names no fact"))
                        })
                    }
                }
                StepKind::EngagementFile => match r.strip_prefix("finding:") {
                    Some("") => Some((
                        LoadErrorKind::MissingField,
                        "`finding:` names its D expectation".into(),
                    )),
                    Some(_) if finding_records == 0 => Some((
                        LoadErrorKind::UnknownValue,
                        format!("`ref = \"{r}\"` files findings no earlier finding_record step recorded"),
                    )),
                    Some(_) => None,
                    None => self.document(r).is_none().then(|| {
                        (
                            LoadErrorKind::DanglingKey,
                            format!("`ref = \"{r}\"` is neither a `[[document]]` nor finding:<expectation>"),
                        )
                    }),
                },
                StepKind::EventRecord => (!self.book.events.iter().any(|e| e.id == r)).then(|| {
                    (LoadErrorKind::DanglingKey, format!("`ref = \"{r}\"` names no `[[event]]`"))
                }),
                StepKind::RuleCheck | StepKind::RulePropose | StepKind::RuleBacktest => {
                    if kind == StepKind::RulePropose {
                        rule_proposes.insert(s.seq);
                    }
                    self.rule_file(r)
                }
                StepKind::MigrateOpen => {
                    migrate_opens.insert(s.seq);
                    self.document(r).is_none().then(|| {
                        (
                            LoadErrorKind::DanglingKey,
                            format!("`ref = \"{r}\"` is not the `[[document]]` of a legacy trial balance"),
                        )
                    })
                }
                StepKind::MigrateFinalize => {
                    let ok = r.parse::<i128>().is_ok_and(|seq| migrate_opens.contains(&seq));
                    (!ok).then(|| {
                        (
                            LoadErrorKind::DanglingKey,
                            format!("`ref = \"{r}\"` is not the seq of an earlier migrate_open step"),
                        )
                    })
                }
                StepKind::MigrateImport => self.import_step(r, &mut import_chunks),
                _ => None,
            };
            if let Some((k, detail)) = problem {
                self.push(ref_line, row, k, detail);
            }
        }
    }

    fn params(
        &mut self,
        i: usize,
        s: &StepDef,
        kind: StepKind,
        params: &[String],
        rule_proposes: &BTreeSet<i128>,
    ) {
        let label = format!("step {}", s.seq);
        let row = Some(label.as_str());
        let line = self.key_line("step", i, "params");
        let reg = self.reg;
        let procedure = s
            .reference
            .split_once('@')
            .and_then(|(id, _)| reg.procedures.as_ref()?.get(id));
        for p in params {
            let Some((name, value)) = p.split_once('=') else {
                self.push(
                    line,
                    row,
                    LoadErrorKind::WrongType,
                    format!("param `{p}` is not `<name>=<value>`"),
                );
                continue;
            };
            let problem = match kind {
                StepKind::FindingRecord => {
                    if procedure
                        .as_ref()
                        .is_some_and(|pr| pr.parameter(name).is_none())
                    {
                        Some(format!(
                            "`{name}` is not a registered parameter of `{}`",
                            s.reference
                        ))
                    } else if value.parse::<i128>().is_err() {
                        Some(format!(
                            "param `{p}`: a finding_record parameter value is an integer"
                        ))
                    } else {
                        None
                    }
                }
                _ => match name {
                    "compare" => (!value
                        .parse::<i128>()
                        .is_ok_and(|seq| rule_proposes.contains(&seq)))
                    .then(|| {
                        format!("`compare={value}` is not the seq of an earlier rule_propose step")
                    }),
                    "from" | "to" => {
                        (!is_date(value)).then(|| format!("`{name}={value}` is a YYYY-MM-DD date"))
                    }
                    other => Some(format!("`{other}` is compare, from or to")),
                },
            };
            if let Some(detail) = problem {
                self.push(line, row, LoadErrorKind::UnknownValue, detail);
            }
        }
    }

    /// `<first>..<last>`: intents in file order, one principal.
    fn range(&self, r: &str) -> Option<(LoadErrorKind, String)> {
        let Some((a, b)) = r.split_once("..") else {
            return Some((
                LoadErrorKind::WrongType,
                format!("`ref = \"{r}\"` is an intent range `<first>..<last>`"),
            ));
        };
        let pos = |id: &str| self.book.intents.iter().position(|i| i.id == id);
        let (Some(pa), Some(pb)) = (pos(a), pos(b)) else {
            return Some((
                LoadErrorKind::DanglingKey,
                format!("`ref = \"{r}\"` names an intent that does not exist"),
            ));
        };
        if pa > pb {
            return Some((
                LoadErrorKind::WrongType,
                format!("`ref = \"{r}\"` runs backwards in file order"),
            ));
        }
        let principals: BTreeSet<&str> = self.book.intents[pa..=pb]
            .iter()
            .map(|i| i.principal.as_str())
            .collect();
        (principals.len() > 1).then(|| {
            (
                LoadErrorKind::UnknownValue,
                format!("the intents of `{r}` have more than one principal ({principals:?})"),
            )
        })
    }

    fn procedure(&self, r: &str) -> Option<(LoadErrorKind, String)> {
        let Some((id, version)) = r.split_once('@') else {
            return Some((
                LoadErrorKind::WrongType,
                format!("`ref = \"{r}\"` is `<procedure id>@<version>`"),
            ));
        };
        let row = self.reg.procedures.as_ref()?.get(id);
        let ok = row.is_some_and(|p| version.parse::<u16>().is_ok_and(|v| v == p.version));
        (!ok).then(|| {
            (
                LoadErrorKind::DanglingKey,
                format!("`{r}` is not a row of registries/procedures.toml"),
            )
        })
    }

    fn rule_file(&self, r: &str) -> Option<(LoadErrorKind, String)> {
        let name = r
            .strip_prefix("rules/")
            .and_then(|n| n.strip_suffix(".rule"));
        if !name.is_some_and(is_word) {
            return Some((
                LoadErrorKind::UnknownValue,
                format!("`ref = \"{r}\"` is a rule source `rules/<name>.rule` of the case"),
            ));
        }
        (!self.view.files.contains(&r)).then(|| {
            (
                LoadErrorKind::DanglingKey,
                format!("`{r}` is not among the case's files"),
            )
        })
    }

    fn import_step<'s>(
        &self,
        r: &'s str,
        chunks: &mut BTreeMap<&'s str, Option<u64>>,
    ) -> Option<(LoadErrorKind, String)> {
        let (id, chunk) = match r.split_once('#') {
            Some((id, c)) => match c.parse::<u64>() {
                Ok(c) => (id, Some(c)),
                Err(_) => {
                    return Some((
                        LoadErrorKind::WrongType,
                        format!("`ref = \"{r}\"`: the chunk is a zero-based integer"),
                    ));
                }
            },
            None => (r, None),
        };
        if !self.book.migration_imports.iter().any(|m| m.id == id) {
            return Some((
                LoadErrorKind::DanglingKey,
                format!("`ref = \"{r}\"` names no `[[migration_import]]`"),
            ));
        }
        match chunk {
            None => {
                if chunks.insert(id, None).is_some() {
                    return Some((
                        LoadErrorKind::DuplicateLabel,
                        format!("import `{id}` is prepared twice"),
                    ));
                }
                None
            }
            Some(c) => {
                let Some(last) = chunks.get_mut(id) else {
                    return Some((
                        LoadErrorKind::UnknownValue,
                        format!("`ref = \"{r}\"` stages a chunk before its import's prepare step"),
                    ));
                };
                let want = last.map_or(0, |l| l + 1);
                if c != want {
                    return Some((
                        LoadErrorKind::UnknownValue,
                        format!("`ref = \"{r}\"`: the next chunk of `{id}` is #{want}"),
                    ));
                }
                *last = Some(c);
                None
            }
        }
    }
}

fn kind_list(kinds: &[StepKind]) -> String {
    kinds
        .iter()
        .map(|k| k.as_str())
        .collect::<Vec<_>>()
        .join(" / ")
}

impl BookVariant {
    /// The file as the TOML subset's document (the canonical-bytes round trip).
    #[must_use]
    pub fn to_document(&self) -> Document {
        let mut doc = Document::default();
        let mut book = Table::new();
        put(&mut book, "variant", &self.book.variant);
        put(&mut book, "opening_date", &self.book.opening_date);
        put(&mut book, "calendar", &self.book.calendar);
        put(&mut book, "base_unit", &self.book.base_unit);
        put(&mut book, "posture", &self.book.posture);
        put_strs(&mut book, "entities", self.book.entities.as_deref());
        put_strs(
            &mut book,
            "entity_relations",
            self.book.entity_relations.as_deref(),
        );
        doc.tables.insert("book".into(), book);
        let mut array = |name: &str, rows: Vec<Table>| {
            if !rows.is_empty() {
                doc.arrays.insert(name.into(), rows);
            }
        };
        array(
            "period",
            self.periods
                .iter()
                .map(|p| {
                    let mut t = Table::new();
                    put(&mut t, "code", &p.code);
                    put(&mut t, "start", &p.start);
                    put(&mut t, "end", &p.end);
                    t.insert("fiscal_year".into(), TomlValue::Int(p.fiscal_year));
                    put(&mut t, "kind", &p.kind);
                    t
                })
                .collect(),
        );
        array(
            "principal",
            self.principals
                .iter()
                .map(|p| {
                    let mut t = Table::new();
                    put(&mut t, "label", &p.label);
                    put(&mut t, "profile", &p.profile);
                    put_strs(&mut t, "grants", Some(&p.grants));
                    t
                })
                .collect(),
        );
        array(
            "account",
            self.accounts
                .iter()
                .map(|a| {
                    let mut t = Table::new();
                    put(&mut t, "code", &a.code);
                    put(&mut t, "name_fact", &a.name_fact);
                    put(&mut t, "type", &a.account_type);
                    put_opt(&mut t, "role", a.role.as_deref());
                    put(&mut t, "opened", &a.opened);
                    put_opt(&mut t, "closed", a.closed.as_deref());
                    put_opt(&mut t, "role_map_rule", a.role_map_rule.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "party",
            self.parties
                .iter()
                .map(|p| {
                    let mut t = Table::new();
                    put(&mut t, "id", &p.id);
                    put(&mut t, "label", &p.label);
                    put(&mut t, "kind", &p.kind);
                    put_strs(&mut t, "relations", p.relations_raw.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "document",
            self.documents
                .iter()
                .map(|d| {
                    let mut t = Table::new();
                    put(&mut t, "id", &d.id);
                    put(&mut t, "stub_of", &d.stub_of);
                    put(&mut t, "grade", &d.grade);
                    put_opt(&mut t, "reviewed_by", d.reviewed_by.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "intent",
            self.intents
                .iter()
                .map(|i| {
                    let mut t = Table::new();
                    put(&mut t, "id", &i.id);
                    put(&mut t, "fact", &i.fact);
                    put(&mut t, "class", &i.class);
                    put(&mut t, "principal", &i.principal);
                    put(&mut t, "effective_date", &i.effective_date);
                    for (k, v) in [
                        ("document_date", &i.document_date),
                        ("memo", &i.memo),
                        ("evidence", &i.evidence),
                        ("idempotency_key", &i.idempotency_key),
                        ("target", &i.target),
                        ("target_kind", &i.target_kind),
                        ("reason", &i.reason),
                        ("scenario", &i.scenario),
                        ("allocation_law", &i.allocation_law),
                        ("allocation_total", &i.allocation_total),
                        ("allocation_source", &i.allocation_source),
                        ("allocation_source_side", &i.allocation_source_side),
                        ("source_entered_by", &i.source_entered_by),
                        ("source_approved_by", &i.source_approved_by),
                    ] {
                        put_opt(&mut t, k, v.as_deref());
                    }
                    put_strs(
                        &mut t,
                        "allocation_targets",
                        i.allocation_targets.as_deref(),
                    );
                    t
                })
                .collect(),
        );
        array(
            "case",
            self.cases
                .iter()
                .map(|c| {
                    let mut t = Table::new();
                    put(&mut t, "id", &c.id);
                    put(&mut t, "kind", &c.kind);
                    put_strs(&mut t, "periods", Some(&c.periods));
                    put(&mut t, "determined_on", &c.determined_on);
                    put(&mut t, "authority", &c.authority);
                    put(&mut t, "disclosure", &c.disclosure);
                    put_strs(&mut t, "approvers", Some(&c.approvers));
                    put(&mut t, "poster", &c.poster);
                    t
                })
                .collect(),
        );
        array(
            "leg",
            self.legs
                .iter()
                .map(|l| {
                    let mut t = Table::new();
                    put(&mut t, "intent", &l.intent);
                    t.insert("ordinal".into(), TomlValue::Int(l.ordinal));
                    put(&mut t, "account", &l.account);
                    put(&mut t, "side", &l.side);
                    put(&mut t, "amount_literal", &l.amount_literal);
                    put(&mut t, "amount_rule", &l.amount_rule);
                    put(&mut t, "unit", &l.unit);
                    put_opt(&mut t, "party", l.party.as_deref());
                    put_opt(&mut t, "entity", l.entity.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "step",
            self.steps
                .iter()
                .map(|s| {
                    let mut t = Table::new();
                    t.insert("seq".into(), TomlValue::Int(s.seq));
                    put(&mut t, "kind", &s.kind);
                    put(&mut t, "ref", &s.reference);
                    put_opt(&mut t, "known_at", s.known_at.as_deref());
                    put_opt(&mut t, "branch_class", s.branch_class.as_deref());
                    put_opt(&mut t, "principal", s.principal.as_deref());
                    put_strs(&mut t, "approvers", s.approvers.as_deref());
                    put_strs(&mut t, "params", s.params.as_deref());
                    put_opt(&mut t, "evidence", s.evidence.as_deref());
                    put_opt(&mut t, "asserts", s.asserts.as_deref());
                    put_opt(&mut t, "document", s.document.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "branch_class",
            self.branch_classes
                .iter()
                .map(|b| {
                    let mut t = Table::new();
                    put(&mut t, "id", &b.id);
                    put(&mut t, "attribute", &b.attribute);
                    put(&mut t, "rule", &b.rule);
                    put_strs(&mut t, "values", Some(&b.values));
                    t
                })
                .collect(),
        );
        array(
            "default",
            self.defaults
                .iter()
                .map(|d| {
                    let mut t = Table::new();
                    put(&mut t, "attribute", &d.attribute);
                    put(&mut t, "rule", &d.rule);
                    put(&mut t, "rationale", &d.rationale);
                    t
                })
                .collect(),
        );
        array(
            "ledger_map",
            self.ledger_maps
                .iter()
                .map(|m| {
                    let mut t = Table::new();
                    put(&mut t, "source", &m.source);
                    put(&mut t, "account", &m.account);
                    put(&mut t, "book_account", &m.book_account);
                    put(&mut t, "party", &m.party);
                    put(&mut t, "cash_account", &m.cash_account);
                    put(&mut t, "transfer_account", &m.transfer_account);
                    put_strs(&mut t, "amount_columns", Some(&m.amount_columns));
                    t
                })
                .collect(),
        );
        array(
            "event",
            self.events
                .iter()
                .map(|e| {
                    let mut t = Table::new();
                    put(&mut t, "id", &e.id);
                    put(&mut t, "kind", &e.kind);
                    put(&mut t, "occurred_on", &e.occurred_on);
                    put_strs(&mut t, "evidence", Some(&e.evidence));
                    put_strs(&mut t, "participants", e.participants.as_deref());
                    put_opt(&mut t, "resource_label", e.resource_label.as_deref());
                    put_opt(
                        &mut t,
                        "resource_amount_literal",
                        e.resource_amount_literal.as_deref(),
                    );
                    put_opt(
                        &mut t,
                        "resource_amount_rule",
                        e.resource_amount_rule.as_deref(),
                    );
                    put_opt(&mut t, "resource_unit", e.resource_unit.as_deref());
                    t
                })
                .collect(),
        );
        array(
            "migration_import",
            self.migration_imports
                .iter()
                .map(|m| {
                    let mut t = Table::new();
                    put(&mut t, "id", &m.id);
                    t.insert("run".into(), TomlValue::Int(m.run));
                    put(&mut t, "source", &m.source);
                    put(&mut t, "format", &m.format);
                    put_strs(&mut t, "account_map", Some(&m.account_map));
                    put_opt(&mut t, "column_map", m.column_map.as_deref());
                    put_opt(&mut t, "default_unit", m.default_unit.as_deref());
                    put_strs(&mut t, "entry_periods", m.entry_periods.as_deref());
                    t
                })
                .collect(),
        );
        doc
    }
}

#[cfg(test)]
#[path = "book_tests.rs"]
mod tests;
