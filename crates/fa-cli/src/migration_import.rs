//! Retained legacy GL sources to independently approved migration chunks.
//!
//! Preparation binds an existing OpeningOnly, PeriodBalances or FullDetail run and its
//! independently declared trial balances to one source, mapping and sealed proposals. The
//! resulting Workpaper is the resume handle. Show and stage replay that complete
//! source closure; staging submits the retained bytes to the native Migration
//! law. Only the existing independently approved finalize operation activates
//! the run, and an explicit abandon leaves its staged history invisible.
//! PeriodBalances names its opening source entries explicitly; every other
//! source entry keeps its effective date in a declared Historical period.
//! FullDetail also preserves earlier history and special-period routing. Its
//! cumulative chain starts from the independently declared detail base, and
//! the native run predicate determines which finalized chunks affect balances.
//! Legacy applications are not reconstructed: settlement-ready opening legs
//! must already represent individual items net of their legacy applications.
//! The package has the admitted Human operator's upload custody, not a
//! Generated-grade receipt. Its source bindings and transformations must replay
//! before inspection or staging; its custody receipt does not prove them.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fa::{Book, BookError};
use fa_formats::legacy::{self, AccountMap, LegacyColumnMap, LegacyFormat, LegacyImportBatch};
use fa_formats::{FormatError, UnitCatalog};
use fa_journal::redaction::DocumentRead;
use fa_journal::{Document, PostRequest, Posted, Run, RunMode, RunState, TieOut, TrialBalanceLine};
use fa_model::{
    ApprovalRef, Entry, EntryOrigin, EntryPayload, Erasable, EvidenceRef, Id128, Oid, Reader,
    Writer, migration_entry_vid, migration_run_vid,
};
use fa_money::{Side, UnitId};
use fa_policy::{Capability, Intent, Op, Profile};
use fa_registry::evidence_policy::EvidencePolicy;
use fa_time::{DateDay, PeriodDef, PeriodKind, PeriodState};
use fgdb_types::VId;

use crate::args::Args;
use crate::cli::{Ctx, Fail, hex, parse_json, render_amount, usage, write_post_plan};
use crate::json::{Json, obj, s};

const EXAMPLE: &str = "fa migrate import --action prepare --intent import.json [--plan-out new.package] | --action show --package D:<oid> | --action stage --package D:<oid> --chunk 0 --approval <vid> --approval <vid>";
const PACKAGE_DOMAIN: &[u8] = b"FA-LEGACY-OPENING-IMPORT\0";
const PACKAGE_VERSION: u16 = 1;
const PACKAGE_MIME: &str = "application/vnd.frankenaccounting.legacy-opening-import.v1";
const PERIOD_BALANCES_DOMAIN: &[u8] = b"FA-LEGACY-PERIOD-BALANCES-IMPORT\0";
const PERIOD_BALANCES_MIME: &str =
    "application/vnd.frankenaccounting.legacy-period-balances-import.v1";
const FULL_DETAIL_DOMAIN: &[u8] = b"FA-LEGACY-FULL-DETAIL-IMPORT\0";
const FULL_DETAIL_MIME: &str = "application/vnd.frankenaccounting.legacy-full-detail-import.v1";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_PACKAGE_BYTES: usize = 16 * 1024 * 1024;
const MAX_CHUNKS: usize = 4096;

impl From<FormatError> for Fail {
    fn from(error: FormatError) -> Self {
        let fix = match &error {
            FormatError::UnmappedAccount { .. } => {
                "supply every legacy account explicitly in the import intent's account_map object, mapped to an existing leaf account code; create missing target accounts before preparing"
            }
            _ => {
                "correct the retained source or explicit account/column mapping, upload the corrected source as a new Document, and prepare a new empty migration run; do not edit an approved package"
            }
        };
        usage(error.to_string(), fix)
    }
}

fn invalid(detail: impl Into<String>) -> Fail {
    Fail::Verification {
        message: format!("invalid legacy migration package: {}", detail.into()),
        detail: obj(Vec::new()),
        cite: Some("plan §8.6; exact retained migration source, proposal and run bindings".into()),
        fix: Some("use the original complete retained Workpaper in its creating book; preserve the source and independently declared trial balance; never regenerate proposals after collecting approvals".into()),
    }
}

fn one<'a>(args: &'a Args, flag: &str) -> Result<Option<&'a str>, Fail> {
    if args.flag_all(flag).len() > 1 {
        return Err(usage(
            format!("migration import takes only one {flag}"),
            EXAMPLE,
        ));
    }
    Ok(args.flag(flag))
}

fn options(args: &Args) -> Result<&str, Fail> {
    if args.positional.len() != 2 {
        return Err(usage(
            "migration import takes an explicit --action",
            EXAMPLE,
        ));
    }
    let action = one(args, "--action")?.ok_or_else(|| {
        usage(
            "migration import requires --action prepare, show or stage",
            EXAMPLE,
        )
    })?;
    let allowed: &[&str] = match action {
        "prepare" => &["--action", "--intent", "--plan-out"],
        "show" => &["--action", "--package"],
        "stage" => &["--action", "--package", "--chunk", "--approval"],
        _ => {
            return Err(usage(
                format!("unknown migration import action `{action}`"),
                EXAMPLE,
            ));
        }
    };
    for flag in [
        "--action",
        "--intent",
        "--plan-out",
        "--package",
        "--chunk",
        "--approval",
        "--run",
        "--period",
        "--key",
        "--evidence",
        "--description",
        "--as-known-at",
        "--known-at",
        "--plan",
    ] {
        if args.flag(flag).is_some() && !allowed.contains(&flag) {
            return Err(usage(
                format!("{flag} does not apply to migration import {action}"),
                EXAMPLE,
            ));
        }
        if flag != "--approval" {
            one(args, flag)?;
        }
    }
    if args.switch("--dry-run") {
        return Err(usage(
            "import prepare retains exact approval material; it does not accept --dry-run",
            EXAMPLE,
        ));
    }
    if let Some(path) = args.flag("--plan-out")
        && (path.is_empty() || path == "-")
    {
        return Err(usage("--plan-out requires a new file path", EXAMPLE));
    }
    Ok(action)
}

fn capability(ctx: &Ctx<'_>, args: &Args, writing: bool) -> Result<Capability, Fail> {
    let ops: &[&str] = if writing {
        &["read", "post", "migrate"]
    } else {
        &["read"]
    };
    let cap = ctx.capability(args, ops)?;
    for name in ops {
        let op = Op::from_name(name)
            .ok_or_else(|| Fail::Internal("migration operation is not registered".into()))?;
        fa_policy::require(&cap, op, "legacy migration import")
            .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    fa_policy::reach(&cap, &fa_policy::Reach::whole_book(true), None)
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    if writing && cap.profile() != Profile::Human {
        return Err(fa_journal::Refusal::new(
            fa_journal::refusal::code::CAPABILITY,
            fa_journal::exit::SAFETY,
            "legacy migration preparation and staging require a Human principal",
            "plan §8.6 and §14.4; approved monetary migration on trunk",
            "use an independently authorized Human operator with read, post and migrate; collect the native independent approvals for each retained chunk",
        ).into());
    }
    Ok(cap)
}

fn admit_book(book: &Book, cap: &Capability, writing: bool) -> Result<(), Fail> {
    if writing {
        fa_policy::admit(
            cap,
            &Intent {
                principal: cap.holder(),
                trunk: true,
                op: Op::Migrate,
                book: book.context().book_id,
                legs: &[],
            },
        )
        .map_err(|denial| Fail::Refusal(fa_journal::policy::refusal(&denial)))?;
    }
    book.read_scope(cap.holder(), cap)??;
    if writing {
        book.preflight_intake(cap, fa::IntakeAction::Upload)??;
    }
    Ok(())
}

fn fixed_hex<const N: usize>(text: &str, what: &str) -> Result<[u8; N], Fail> {
    if text.len() != N * 2 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(usage(
            format!("{what} needs exactly {} hexadecimal digits", N * 2),
            EXAMPLE,
        ));
    }
    let mut value = [0; N];
    for (byte, pair) in value.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        let pair =
            std::str::from_utf8(pair).map_err(|_| usage(format!("invalid {what}"), EXAMPLE))?;
        *byte =
            u8::from_str_radix(pair, 16).map_err(|_| usage(format!("invalid {what}"), EXAMPLE))?;
    }
    Ok(value)
}

fn oid(text: &str, what: &str) -> Result<Oid, Fail> {
    Ok(Oid(fixed_hex(
        text.strip_prefix("D:").unwrap_or(text),
        what,
    )?))
}

fn run_vid(book: Id128, text: &str) -> Result<VId, Fail> {
    if let Some(vid) = text.strip_prefix("MR:") {
        return Ok(VId(u128::from_be_bytes(fixed_hex(vid, "run")?)));
    }
    if text.len() == 32 && text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(VId(u128::from_be_bytes(fixed_hex(text, "run")?)));
    }
    if text.is_empty() {
        return Err(usage(
            "run must be an existing migration run key or MR:<vid>",
            EXAMPLE,
        ));
    }
    Ok(migration_run_vid(book, text))
}

fn required_text<'a>(value: &'a Json, key: &str) -> Result<&'a str, Fail> {
    value
        .get(key)
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            usage(
                format!("import intent `{key}` must be a nonempty string"),
                EXAMPLE,
            )
        })
}

fn optional_text(value: &Json, key: &str) -> Result<Option<String>, Fail> {
    match value.get(key) {
        None => Ok(None),
        Some(Json::Str(text)) if !text.is_empty() => Ok(Some(text.clone())),
        Some(_) => Err(usage(
            format!("import intent `{key}` must be a nonempty string when supplied"),
            EXAMPLE,
        )),
    }
}

struct ImportRequest {
    run: VId,
    source: Oid,
    format: LegacyFormat,
    default_unit: Option<String>,
    account_map: BTreeMap<String, String>,
    column_map: Option<String>,
    opening_entries: Option<BTreeSet<String>>,
    entry_periods: Option<BTreeMap<String, String>>,
}

fn format_name(format: LegacyFormat) -> &'static str {
    match format {
        LegacyFormat::QuickBooksIif => "quickbooks-iif",
        LegacyFormat::QuickBooksCsv => "quickbooks-csv",
        LegacyFormat::XeroCsv => "xero-csv",
        LegacyFormat::NetSuiteCsv => "netsuite-csv",
        LegacyFormat::GenericCsv => "csv",
        LegacyFormat::Beancount => "beancount",
        LegacyFormat::Hledger => "hledger",
    }
}

impl ImportRequest {
    fn parse(book_id: Id128, text: &str) -> Result<Self, Fail> {
        let value = parse_json("legacy import intent", text)?;
        let Json::Obj(fields) = &value else {
            return Err(usage("legacy import intent must be a JSON object", EXAMPLE));
        };
        let mut seen = BTreeSet::new();
        for (key, _) in fields {
            if !matches!(
                key.as_str(),
                "run"
                    | "source"
                    | "format"
                    | "default_unit"
                    | "account_map"
                    | "column_map"
                    | "opening_entries"
                    | "entry_periods"
            ) || !seen.insert(key)
            {
                return Err(usage(
                    format!("unknown or repeated import intent field `{key}`"),
                    EXAMPLE,
                ));
            }
        }
        let format = match required_text(&value, "format")? {
            "quickbooks-iif" => LegacyFormat::QuickBooksIif,
            "quickbooks-csv" => LegacyFormat::QuickBooksCsv,
            "xero-csv" => LegacyFormat::XeroCsv,
            "netsuite-csv" => LegacyFormat::NetSuiteCsv,
            "csv" => LegacyFormat::GenericCsv,
            "beancount" => LegacyFormat::Beancount,
            "hledger" => LegacyFormat::Hledger,
            _ => {
                return Err(usage(
                    "unsupported legacy source format",
                    "format: quickbooks-iif | quickbooks-csv | xero-csv | netsuite-csv | csv | beancount | hledger",
                ));
            }
        };
        let Some(Json::Obj(mappings)) = value.get("account_map") else {
            return Err(usage(
                "account_map must be an object mapping legacy identifiers to target leaf codes",
                "\"account_map\": {\"Legacy Cash\": \"1000\", \"Legacy Equity\": \"3000\"}",
            ));
        };
        if mappings.is_empty() || mappings.len() > MAX_CHUNKS {
            return Err(usage(
                format!("account_map needs 1..={MAX_CHUNKS} explicit mappings"),
                EXAMPLE,
            ));
        }
        let mut account_map = BTreeMap::new();
        for (legacy, target) in mappings {
            let target = target
                .as_str()
                .filter(|text| !text.is_empty())
                .ok_or_else(|| {
                    usage(
                        "every account_map value must be a nonempty leaf code",
                        EXAMPLE,
                    )
                })?;
            if legacy.trim().is_empty()
                || legacy.trim() != legacy
                || account_map
                    .insert(legacy.clone(), target.to_string())
                    .is_some()
            {
                return Err(usage(
                    "account_map keys must be unique, nonempty and have no surrounding whitespace",
                    EXAMPLE,
                ));
            }
        }
        let column_map = optional_text(&value, "column_map")?;
        if (format == LegacyFormat::GenericCsv) != column_map.is_some() {
            return Err(usage(
                "column_map is required exactly for format csv",
                "include a TOML [columns] string in column_map for generic CSV; keep all account mappings in account_map",
            ));
        }
        let opening_entries = match value.get("opening_entries") {
            None => None,
            Some(Json::Arr(entries)) if !entries.is_empty() && entries.len() <= MAX_CHUNKS => {
                let mut selected = BTreeSet::new();
                for entry in entries {
                    let id = entry.as_str().filter(|id| !id.is_empty() && id.trim() == *id)
                        .ok_or_else(|| usage(
                            "opening_entries must contain exact nonempty legacy source entry IDs without surrounding whitespace",
                            "list the source journal IDs that represent opening stock; entries on the opening date are not assumed to be opening stock",
                        ))?;
                    if !selected.insert(id.to_owned()) {
                        return Err(usage("opening_entries repeats a source entry ID", EXAMPLE));
                    }
                }
                Some(selected)
            }
            Some(_) => {
                return Err(usage(
                    format!(
                        "opening_entries must be an array of 1..={MAX_CHUNKS} source entry IDs"
                    ),
                    "PeriodBalances and non-sole FullDetail require explicit opening_entries; omit it for OpeningOnly and sole-source FullDetail",
                ));
            }
        };
        let entry_periods = match value.get("entry_periods") {
            None => None,
            Some(Json::Obj(entries)) if entries.len() <= MAX_CHUNKS => {
                let mut periods = BTreeMap::new();
                for (id, period) in entries {
                    let code = period
                        .as_str()
                        .filter(|code| !code.is_empty() && code.trim() == *code)
                        .ok_or_else(|| usage(
                            "entry_periods values must be exact nonempty fiscal period codes",
                            "name the source journal's actual period, including its Opening, Adjustment or Closing discriminator when applicable",
                        ))?;
                    if id.is_empty()
                        || id.trim() != id
                        || periods.insert(id.clone(), code.to_owned()).is_some()
                    {
                        return Err(usage(
                            "entry_periods keys must be unique exact nonempty source journal IDs without surrounding whitespace",
                            "use each original source journal ID once; the importer never guesses a special period from descriptions or amounts",
                        ));
                    }
                }
                Some(periods)
            }
            Some(_) => {
                return Err(usage(
                    format!(
                        "entry_periods must be an object with at most {MAX_CHUNKS} source journal IDs"
                    ),
                    "FullDetail accepts entry_periods: {\"legacy-close\": \"FY2025-CLOSE\"}; omit the field for other modes",
                ));
            }
        };
        Ok(Self {
            run: run_vid(book_id, required_text(&value, "run")?)?,
            source: oid(required_text(&value, "source")?, "source")?,
            format,
            default_unit: optional_text(&value, "default_unit")?,
            account_map,
            column_map,
            opening_entries,
            entry_periods,
        })
    }

    fn canonical_text(&self) -> String {
        let mut fields = vec![
            ("run", s(format!("MR:{:032x}", self.run.0))),
            ("source", s(hex(&self.source.0))),
            ("format", s(format_name(self.format))),
            (
                "account_map",
                Json::Obj(
                    self.account_map
                        .iter()
                        .map(|(legacy, target)| (legacy.clone(), s(target)))
                        .collect(),
                ),
            ),
        ];
        if let Some(unit) = &self.default_unit {
            fields.push(("default_unit", s(unit)));
        }
        if let Some(columns) = &self.column_map {
            fields.push(("column_map", s(columns)));
        }
        if let Some(entries) = &self.opening_entries {
            fields.push((
                "opening_entries",
                Json::Arr(entries.iter().map(s).collect()),
            ));
        }
        if let Some(periods) = &self.entry_periods {
            fields.push((
                "entry_periods",
                Json::Obj(
                    periods
                        .iter()
                        .map(|(id, period)| (id.clone(), s(period)))
                        .collect(),
                ),
            ));
        }
        obj(fields).render()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PackageKind {
    OpeningOnly,
    PeriodBalances,
    FullDetail,
}

impl PackageKind {
    fn for_run(run: &Run) -> Self {
        match run.body.mode {
            RunMode::OpeningOnly => Self::OpeningOnly,
            RunMode::PeriodBalances => Self::PeriodBalances,
            RunMode::FullDetail => Self::FullDetail,
        }
    }

    fn domain(self) -> &'static [u8] {
        match self {
            Self::OpeningOnly => PACKAGE_DOMAIN,
            Self::PeriodBalances => PERIOD_BALANCES_DOMAIN,
            Self::FullDetail => FULL_DETAIL_DOMAIN,
        }
    }

    fn mime(self) -> &'static str {
        match self {
            Self::OpeningOnly => PACKAGE_MIME,
            Self::PeriodBalances => PERIOD_BALANCES_MIME,
            Self::FullDetail => FULL_DETAIL_MIME,
        }
    }

    fn mode_name(self) -> &'static str {
        match self {
            Self::OpeningOnly => "OpeningOnly",
            Self::PeriodBalances => "PeriodBalances",
            Self::FullDetail => "FullDetail",
        }
    }
}

struct Package {
    kind: PackageKind,
    book_id: Id128,
    run: VId,
    run_body_digest: [u8; 32],
    source: Oid,
    source_commit: [u8; 32],
    request: Erasable<String>,
    proposals: Vec<EntryPayload>,
}

impl Package {
    fn encode(&self) -> Result<Vec<u8>, Fail> {
        let mut writer = Writer::new();
        writer
            .fixed(self.kind.domain())
            .u16(PACKAGE_VERSION)
            .fixed(&self.book_id.0)
            .u128(self.run.0)
            .fixed(&self.run_body_digest)
            .fixed(&self.source.0)
            .fixed(&self.source_commit);
        self.request.encode(&mut writer);
        writer.u32(u32::try_from(self.proposals.len()).map_err(|_| invalid("too many proposals"))?);
        for proposal in &self.proposals {
            let bytes = proposal.clone().seal(Vec::new(), None).and_then(|entry| entry.encode())
                .map_err(|error| usage(format!("legacy proposal violates the native schema: {error}"), "correct the source field or split the source into bounded complete migration runs"))?;
            if writer.len().saturating_add(4).saturating_add(bytes.len()) > MAX_PACKAGE_BYTES {
                return Err(usage(
                    "complete legacy import package exceeds 16 MiB",
                    "split the source into explicitly separate runs and independently declared trial balances; no partial package was retained",
                ));
            }
            writer.bytes(&bytes);
        }
        writer.finish().map_err(|error| invalid(error.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, Fail> {
        if bytes.len() > MAX_PACKAGE_BYTES {
            return Err(invalid("package exceeds 16 MiB"));
        }
        let kind = if bytes.starts_with(PACKAGE_DOMAIN) {
            PackageKind::OpeningOnly
        } else if bytes.starts_with(PERIOD_BALANCES_DOMAIN) {
            PackageKind::PeriodBalances
        } else if bytes.starts_with(FULL_DETAIL_DOMAIN) {
            PackageKind::FullDetail
        } else {
            return Err(invalid("unsupported package domain"));
        };
        let mut reader = Reader::new(&bytes[kind.domain().len()..]);
        let decode = |error: fa_model::DecodeError| invalid(error.to_string());
        if reader.u16("legacy_import.version").map_err(decode)? != PACKAGE_VERSION {
            return Err(invalid("unsupported package version"));
        }
        let book_id = Id128(reader.fixed("legacy_import.book").map_err(decode)?);
        let run = VId(reader.u128("legacy_import.run").map_err(decode)?);
        let run_body_digest = reader.fixed("legacy_import.run_body").map_err(decode)?;
        let source = Oid(reader.fixed("legacy_import.source").map_err(decode)?);
        let source_commit = reader
            .fixed("legacy_import.source_commit")
            .map_err(decode)?;
        let request = Erasable::decode(&mut reader, MAX_REQUEST_BYTES).map_err(decode)?;
        let count = reader
            .count(MAX_CHUNKS, "legacy_import.proposals")
            .map_err(decode)?;
        if count == 0 {
            return Err(invalid("package has no proposals"));
        }
        let mut proposals = Vec::with_capacity(count);
        for _ in 0..count {
            let payload = reader
                .bytes(fa_model::limits::MAX_ENTRY_BYTES, "legacy_import.proposal")
                .map_err(decode)?;
            let entry = Entry::decode(payload).map_err(|error| invalid(error.to_string()))?;
            if !entry.approvals.is_empty() || entry.plan_certificate.is_some() {
                return Err(invalid(
                    "package must retain proposals before their independent approvals",
                ));
            }
            proposals.push(entry.proposal);
        }
        reader.finish().map_err(decode)?;
        Ok(Self {
            kind,
            book_id,
            run,
            run_body_digest,
            source,
            source_commit,
            request,
            proposals,
        })
    }
}

fn full_document(book: &mut Book, cap: &Capability, oid: Oid) -> Result<Document, Fail> {
    let read = match book.read_document_for(cap, &oid)? {
        Ok(read) => read,
        Err(mut refusal) => {
            if refusal.code == "FA-REF-142" {
                refusal.fix.push_str("; legacy import must replay the full original source, so an independently authorized embedded owner can explicitly add --grant privileged; a launch-bound session cannot grant itself this authority");
            }
            return Err(refusal.into());
        }
    };
    match read {
        DocumentRead::Full(document) => Ok(document),
        DocumentRead::Redacted(_) => Err(fa_journal::Refusal::new(
            fa_journal::refusal::code::CAPABILITY,
            fa_journal::exit::SAFETY,
            "legacy migration requires authorized access to the complete retained source and trial balance",
            "plan §8.6 and §14.6; exact source replay cannot use a redacted projection",
            "use an operator authorized to read the complete source; an embedded owner may explicitly add --grant privileged; a launch-bound capability cannot widen itself",
        ).into()),
    }
}

fn load_run(book: &Book, vid: VId) -> Result<Run, Fail> {
    let run = book.migration_run(vid, None)?.ok_or_else(|| usage("the selected migration run does not exist", "open an OpeningOnly, PeriodBalances or FullDetail run with independently retained trial balance documents and exact typed lines before importing"))?;
    if run.body.lines.is_empty()
        && !(run.body.mode == RunMode::FullDetail && run.body.sole_opening_source)
    {
        return Err(usage(
            "a run with separate opening stock requires independently declared opening lines",
            "declare exact opening lines, or use FullDetail sole_opening_source with neither opening lines nor detail_base when historical detail is the entire source of balances",
        ));
    }
    Ok(run)
}

fn opening_period(book: &Book, run: &Run, preparing: bool) -> Result<String, Fail> {
    if run.body.mode == RunMode::FullDetail && run.body.sole_opening_source {
        // Native sole-source runs post no own Opening chunk. Its code is a
        // calendar label, not an instruction to create or lock a period that
        // may lie outside the complete historical span.
        let calendar = &book.context().calendar;
        let fiscal_year = calendar
            .fiscal_year_of(run.body.opening_date)
            .map_err(|error| {
                invalid(format!(
                    "run opening date is outside the calendar: {error:?}"
                ))
            })?;
        return calendar
            .periods_for_year(fiscal_year)
            .map_err(|error| invalid(format!("run opening calendar is unavailable: {error:?}")))?
            .into_iter()
            .find(|period| period.kind == PeriodKind::Opening)
            .map(|period| period.code)
            .ok_or_else(|| invalid("the run's fiscal year has no Opening period"));
    }
    let candidates: Vec<_> = book
        .periods()?
        .into_iter()
        .filter(|period| {
            period.kind == PeriodKind::Opening
                && period.start == run.body.opening_date
                && period.calendar_id == book.context().calendar.id
        })
        .collect();
    let [period] = candidates.as_slice() else {
        return Err(usage(
            "the run needs exactly one existing Opening period at its opening date",
            "create the run's fiscal-year periods and lock its own Opening period through the native period workflow",
        ));
    };
    if preparing && period.state != PeriodState::Locked {
        return Err(usage(
            "the run's Opening period must be Locked before preparing migration chunks",
            "use the existing approved period workflow; the importer never changes period states",
        ));
    }
    Ok(period.code.clone())
}

fn parse_source(
    book: &Book,
    request: &mut ImportRequest,
    run: &Run,
    source: &Document,
) -> Result<LegacyImportBatch, Fail> {
    if source.oid() != request.source || source.book_id != book.context().book_id {
        return Err(invalid("source identity or book does not match"));
    }
    if run.body.documents().contains(&request.source) {
        return Err(usage(
            "the source and every independently declared trial balance must be distinct retained Documents",
            "retain the opening and per-period legacy trial balances separately from the journal source, declare their exact lines when opening the run, then import the original export",
        ));
    }
    match (run.body.mode, &request.opening_entries) {
        (RunMode::OpeningOnly, Some(_)) => {
            return Err(usage(
                "opening_entries applies only to PeriodBalances and non-sole FullDetail imports",
                "omit opening_entries for OpeningOnly; that mode imports the complete source as opening stock",
            ));
        }
        (RunMode::PeriodBalances, None) => {
            return Err(usage(
                "PeriodBalances requires explicit opening_entries",
                "list the exact source journal IDs representing opening stock; all other entries keep their source dates in the run's declared Historical periods",
            ));
        }
        (RunMode::FullDetail, Some(_)) if run.body.sole_opening_source => {
            return Err(usage(
                "sole-source FullDetail has no opening_entries",
                "omit opening_entries; every source journal is dated historical detail, and the native sole-source run admits no separate own Opening chunk",
            ));
        }
        (RunMode::FullDetail, None) if !run.body.sole_opening_source => {
            return Err(usage(
                "non-sole FullDetail requires explicit opening_entries",
                "list source journals representing separate opening stock; all remaining journals retain their dates in the declared historical span",
            ));
        }
        _ => {}
    }
    if request.entry_periods.is_some() && run.body.mode != RunMode::FullDetail {
        return Err(usage(
            "entry_periods applies only to FullDetail imports",
            "omit entry_periods for OpeningOnly or PeriodBalances; FullDetail explicitly distinguishes dated historical opening, adjustment and closing journals",
        ));
    }
    let source_text = std::str::from_utf8(&source.bytes).map_err(|_| {
        usage(
            "legacy source must be complete UTF-8 text",
            "retain the original decoded UTF-8 IIF or CSV export as a Document",
        )
    })?;
    let accounts = book.accounts()?;
    let mut account_map = AccountMap::new(
        accounts
            .iter()
            .filter(|account| account.is_leaf)
            .map(|account| account.code.clone()),
    );
    account_map.allow_passthrough_leaf_codes = false;
    for (legacy, target) in &request.account_map {
        if !account_map.valid_leaf_accounts.contains(target) {
            return Err(usage(
                format!("account_map target `{target}` is not an existing leaf account"),
                "create the intended target leaf account or correct the explicit account_map before preparing",
            ));
        }
        account_map.insert(legacy, target);
    }
    let context = book.context();
    let units = UnitCatalog::embedded()?;
    let default_unit = match &request.default_unit {
        Some(unit) => unit.clone(),
        None => context
            .units
            .get(book.spec()?.base_unit)
            .map(|unit| unit.code.clone())
            .ok_or_else(|| Fail::Internal("book base unit is absent from its registry".into()))?,
    };
    let unit_id = context.units.lookup(&default_unit).ok_or_else(|| {
        usage(
            "default_unit is not registered in the selected book",
            "choose the book's exact registered unit code",
        )
    })?;
    let unit = context
        .units
        .get(unit_id)
        .ok_or_else(|| Fail::Internal("book unit index is inconsistent".into()))?;
    if units.lookup_code(&default_unit) != Some((unit_id, unit.scale)) {
        return Err(usage(
            "legacy parser and selected book disagree on the default unit's identity or scale",
            "use the parser and unit registry matching the book; never reinterpret fixed-scale amounts",
        ));
    }
    request.default_unit = Some(default_unit.clone());
    let batch = match request.format {
        LegacyFormat::QuickBooksIif => {
            legacy::parse_quickbooks_iif(source_text, &units, &account_map, &default_unit)?
        }
        LegacyFormat::QuickBooksCsv => {
            legacy::parse_quickbooks_csv(source_text, &units, &account_map, &default_unit)?
        }
        LegacyFormat::XeroCsv => {
            legacy::parse_xero_csv(source_text, &units, &account_map, &default_unit)?
        }
        LegacyFormat::NetSuiteCsv => {
            legacy::parse_netsuite_csv(source_text, &units, &account_map, &default_unit)?
        }
        LegacyFormat::GenericCsv => {
            let raw = request
                .column_map
                .as_deref()
                .ok_or_else(|| usage("generic CSV requires column_map", EXAMPLE))?;
            let mut columns = LegacyColumnMap::parse_toml(raw)?;
            if !columns.account_mappings.is_empty() {
                return Err(usage(
                    "column_map must not contain a second account_map",
                    "keep column declarations in column_map and every explicit legacy-to-leaf mapping in the intent's account_map object",
                ));
            }
            let declares_default = raw
                .lines()
                .filter_map(|line| line.split_once('='))
                .any(|(key, _)| matches!(key.trim(), "default_unit" | "\"default_unit\""));
            if declares_default && columns.default_unit != default_unit {
                return Err(usage(
                    "column_map default_unit conflicts with the import intent's default or book base unit",
                    "declare default_unit in the import intent and remove or match the column_map declaration; never silently reinterpret source amounts",
                ));
            }
            // The explicit intent default, or the book's base unit, is the
            // single default for every format; the generic parser's USD
            // fallback must not silently reinterpret a non-USD book.
            columns.default_unit = default_unit;
            legacy::parse_generic_csv(source_text, &columns, &units, &account_map)?
        }
        LegacyFormat::Beancount => {
            legacy::parse_beancount_ledger(source_text, &units, &account_map)?
        }
        LegacyFormat::Hledger => legacy::parse_hledger_journal(source_text, &units, &account_map)?,
    };
    if batch.chunks.len() > MAX_CHUNKS {
        return Err(usage(
            format!("legacy source exceeds {MAX_CHUNKS} complete entries per package"),
            "split it into explicit runs, each with its own independently declared trial balance",
        ));
    }
    if batch.source_system != run.body.source_system {
        return Err(usage(
            "parsed source system differs from the migration run's declared source_system",
            "open the run for the selected parser's source system, or set the generic column_map source_system to the independently declared name",
        ));
    }
    for chunk in &batch.chunks {
        if run.body.mode == RunMode::OpeningOnly && chunk.effective_date > run.body.opening_date {
            return Err(usage(
                "OpeningOnly import contains a source entry dated after the run opening date",
                "retain an export cut off at the opening date; this workflow preserves earlier dates as document_date and does not claim historical-period replay",
            ));
        }
        for leg in &chunk.legs {
            let registered = context.units.get(leg.amount.unit).ok_or_else(|| {
                usage(
                    "a source leg names a unit absent from the book",
                    "use the unit registry matching the book",
                )
            })?;
            if registered.code != leg.unit_code || registered.scale != leg.unit_scale {
                return Err(usage(
                    "a source leg's unit identity or scale differs from the selected book",
                    "use the parser and registry matching the book; do not round or coerce amounts",
                ));
            }
            if accounts
                .iter()
                .any(|account| account.code == leg.account_code && account.limit.is_some())
            {
                return Err(usage(
                    "native Migration does not support balance-limited target accounts",
                    "use the native supported migration chart; do not remove account limits to force an import",
                ));
            }
        }
    }
    if run.body.mode == RunMode::OpeningOnly && batch.trial_balance != run.body.lines {
        return Err(usage(
            "the complete mapped source does not tie exactly to the run's independently declared trial balance",
            "reconcile the legacy source, account mapping and declared trial balance before preparing; no package or chunk was recorded",
        ));
    }
    Ok(batch)
}

struct SourceRoute {
    date: DateDay,
    period: String,
}

type BalanceFold = BTreeMap<(String, UnitId), i128>;

fn add_balance(
    fold: &mut BalanceFold,
    account: &str,
    unit: UnitId,
    amount: i128,
) -> Result<(), Fail> {
    let cell = fold.entry((account.to_owned(), unit)).or_insert(0);
    *cell = cell.checked_add(amount).ok_or_else(|| usage(
        "legacy period trial balance exceeds exact fixed-scale arithmetic bounds",
        "reconcile the source and account mapping; the importer never wraps, rounds or inserts a balancing leg",
    ))?;
    Ok(())
}

fn check_balance(fold: &BalanceFold, lines: &[TrialBalanceLine], at: &str) -> Result<(), Fail> {
    let actual: Vec<_> = fold
        .iter()
        .filter(|(_, amount)| **amount != 0)
        .map(|((account, unit), amount)| TrialBalanceLine {
            account_code: account.clone(),
            unit: *unit,
            mantissa: *amount,
        })
        .collect();
    if actual != lines {
        return Err(usage(
            format!(
                "the complete mapped source does not tie exactly to the independently declared trial balance {at}"
            ),
            "reconcile the opening entry selection, source dates, account mapping and every declared cumulative period balance; no package or chunk was recorded",
        ));
    }
    Ok(())
}

fn full_detail_routes(
    book: &Book,
    request: &ImportRequest,
    run: &Run,
    batch: &LegacyImportBatch,
    opening: &str,
) -> Result<Vec<SourceRoute>, Fail> {
    let calendar = &book.context().calendar;
    let rows = book.periods()?;
    let mut declared_rows = Vec::with_capacity(run.body.periods.len());
    for declared in &run.body.periods {
        let row = rows
            .iter()
            .find(|row| row.calendar_id == calendar.id && row.code == declared.period_code)
            .ok_or_else(|| invalid("a declared FullDetail Historical period is absent"))?;
        if row.kind != PeriodKind::Historical || row.state != PeriodState::Locked {
            return Err(invalid(
                "FullDetail requires each declared Normal period to be born Historical and Locked",
            ));
        }
        declared_rows.push(row);
    }
    let (Some(first), Some(last)) = (declared_rows.first(), declared_rows.last()) else {
        return Err(invalid("FullDetail has no declared Historical span"));
    };
    let (from, to) = (first.start, last.end);
    let go_live = book
        .spec()?
        .opening_date
        .ok_or_else(|| invalid("FullDetail needs the book's declared opening date"))?;
    if from >= to || to > go_live || (!run.body.sole_opening_source && from > run.body.opening_date)
    {
        return Err(invalid(
            "FullDetail's declared span does not cover its required historical opening chain",
        ));
    }
    let first_year = calendar.fiscal_year_of(from).map_err(|error| {
        invalid(format!(
            "historical span starts outside the calendar: {error:?}"
        ))
    })?;
    let last_year = calendar.fiscal_year_of(to).map_err(|error| {
        invalid(format!(
            "historical span ends outside the calendar: {error:?}"
        ))
    })?;
    let mut order = Vec::new();
    for fiscal_year in first_year..=last_year {
        for period in calendar.periods_for_year(fiscal_year).map_err(|error| {
            invalid(format!(
                "historical fiscal calendar is unavailable: {error:?}"
            ))
        })? {
            if period.start >= from && period.end <= to && period.code != opening {
                order.push(period);
            }
        }
    }
    // Match native FullDetail ordering: Opening, Normal, Adjustment, Closing.
    // Adjustment ordinal breaks ties in the same order as calendar generation.
    order.sort_by_key(PeriodDef::chronological_key);
    if order
        .iter()
        .filter(|period| period.kind == PeriodKind::Normal)
        .map(|period| period.code.as_str())
        .ne(run
            .body
            .periods
            .iter()
            .map(|period| period.period_code.as_str()))
    {
        return Err(invalid(
            "FullDetail's declared Normal periods are not the complete contiguous calendar span",
        ));
    }
    let mut seen_ids = BTreeSet::new();
    let mut seen_opening = BTreeSet::new();
    let mut opening_fold = BalanceFold::new();
    let mut period_folds: BTreeMap<&str, BalanceFold> = BTreeMap::new();
    let mut routes = Vec::with_capacity(batch.chunks.len());
    for (index, chunk) in batch.chunks.iter().enumerate() {
        let id = chunk.provenance.source_id.as_str();
        if !seen_ids.insert(id) {
            return Err(usage(
                "FullDetail source journal IDs are ambiguous",
                "retain a source export with one unique ID per journal; entry_periods and opening_entries never select a guessed row",
            ));
        }
        let named = request
            .entry_periods
            .as_ref()
            .and_then(|periods| periods.get(id));
        let is_opening = request
            .opening_entries
            .as_ref()
            .is_some_and(|entries| entries.contains(id));
        let (route, fold) = if is_opening {
            if named.is_some() {
                return Err(usage(
                    "a source journal occurs in both opening_entries and entry_periods",
                    "select separate opening stock with opening_entries, and route historical detail with entry_periods; a journal cannot serve both purposes",
                ));
            }
            if chunk.effective_date > run.body.opening_date {
                return Err(usage(
                    "a selected opening entry is dated after the run opening date",
                    "select opening-stock journals dated on or before the run's fiscal-year start; historical detail preserves its source dates",
                ));
            }
            seen_opening.insert(id);
            (
                SourceRoute {
                    date: run.body.opening_date,
                    period: opening.to_owned(),
                },
                &mut opening_fold,
            )
        } else {
            let period = if let Some(code) = named {
                order
                    .iter()
                    .find(|period| period.code == *code && period.contains(chunk.effective_date))
                    .ok_or_else(|| usage(
                        format!("source entry {index} names a period outside its source date or the run's admitted FullDetail span"),
                        "entry_periods must name a declared Historical Normal period or an Opening, Adjustment or Closing period inside that span; own opening stock belongs only in opening_entries",
                    ))?
            } else {
                let candidates: Vec<_> = order
                    .iter()
                    .filter(|period| period.contains(chunk.effective_date))
                    .collect();
                let [period] = candidates.as_slice() else {
                    return Err(usage(
                        format!(
                            "source entry {index} does not resolve to one unambiguous FullDetail period"
                        ),
                        "supply entry_periods for dates shared by historical Normal, Opening, Adjustment or Closing periods; include only detail in the declared span and never infer a closing journal from its description",
                    ));
                };
                *period
            };
            let row = rows
                .iter()
                .find(|row| row.calendar_id == calendar.id && row.code == period.code)
                .ok_or_else(|| usage(
                    format!("source entry {index} targets a fiscal period that has not been created"),
                    "create the historical fiscal year's native periods before preparing; the importer never creates or transitions periods",
                ))?;
            let expected_kind = if period.kind == PeriodKind::Normal {
                PeriodKind::Historical
            } else {
                period.kind
            };
            if row.kind != expected_kind
                || row.state != PeriodState::Locked
                || row.start != period.start
                || row.end != period.end
            {
                return Err(invalid(
                    "a FullDetail destination is not the matching locked historical calendar period",
                ));
            }
            (
                SourceRoute {
                    date: chunk.effective_date,
                    period: period.code.clone(),
                },
                period_folds.entry(period.code.as_str()).or_default(),
            )
        };
        // Preserve every source leg and its ordinal. In particular, separate
        // net open-invoice legs must never collapse into an account total.
        for leg in &chunk.legs {
            let amount = match leg.side {
                Side::Debit => leg.amount.mantissa,
                Side::Credit => leg
                    .amount
                    .mantissa
                    .checked_neg()
                    .ok_or_else(|| invalid("source credit cannot be negated exactly"))?,
            };
            add_balance(fold, &leg.account_code, leg.amount.unit, amount)?;
        }
        routes.push(route);
    }
    if request
        .opening_entries
        .as_ref()
        .is_some_and(|selected| selected.len() != seen_opening.len())
    {
        return Err(usage(
            "opening_entries contains an ID absent from the complete source",
            "use exact source journal IDs for the separate opening-stock entries",
        ));
    }
    if request
        .entry_periods
        .as_ref()
        .is_some_and(|periods| periods.keys().any(|id| !seen_ids.contains(id.as_str())))
    {
        return Err(usage(
            "entry_periods contains an ID absent from the complete source",
            "map only exact retained source journal IDs; period selections remain private sealed configuration",
        ));
    }
    check_balance(&opening_fold, &run.body.lines, "at the opening")?;
    let mut chain = BalanceFold::new();
    for line in &run.body.detail_base {
        add_balance(&mut chain, &line.account_code, line.unit, line.mantissa)?;
    }
    let mut opening_checked = run.body.sole_opening_source;
    for period in &order {
        if !opening_checked && period.start >= run.body.opening_date {
            check_balance(
                &chain,
                &run.body.lines,
                "at the historical opening boundary",
            )?;
            opening_checked = true;
        }
        if let Some(movement) = period_folds.get(period.code.as_str()) {
            for ((account, unit), amount) in movement {
                add_balance(&mut chain, account, *unit, *amount)?;
            }
        }
        if let Some(declared) = run
            .body
            .periods
            .iter()
            .find(|declared| declared.period_code == period.code)
        {
            // A Normal period's checkpoint is pre-adjustment and pre-closing;
            // quiet periods still tie out without an invented zero-value JE.
            check_balance(
                &chain,
                &declared.lines,
                &format!("through `{}`", period.code),
            )?;
        }
    }
    if !opening_checked {
        check_balance(
            &chain,
            &run.body.lines,
            "at the historical opening boundary",
        )?;
    }
    Ok(routes)
}

fn source_routes(
    book: &Book,
    request: &ImportRequest,
    run: &Run,
    batch: &LegacyImportBatch,
    opening: &str,
) -> Result<Vec<SourceRoute>, Fail> {
    if run.body.mode == RunMode::OpeningOnly {
        return Ok(batch
            .chunks
            .iter()
            .map(|_| SourceRoute {
                date: run.body.opening_date,
                period: opening.to_owned(),
            })
            .collect());
    }
    if run.body.mode == RunMode::FullDetail {
        return full_detail_routes(book, request, run, batch, opening);
    }
    let selected = request
        .opening_entries
        .as_ref()
        .ok_or_else(|| invalid("PeriodBalances has no opening entry selection"))?;
    let rows = book.periods()?;
    let go_live = book
        .spec()?
        .opening_date
        .ok_or_else(|| invalid("PeriodBalances needs the book's declared opening date"))?;
    let mut periods = Vec::with_capacity(run.body.periods.len());
    for declared in &run.body.periods {
        let row = rows
            .iter()
            .find(|row| {
                row.code == declared.period_code && row.calendar_id == book.context().calendar.id
            })
            .ok_or_else(|| invalid("a declared Historical period is absent"))?;
        if row.kind != PeriodKind::Historical
            || row.state != PeriodState::Locked
            || row.start < run.body.opening_date
            || row.end > go_live
        {
            return Err(invalid(
                "a declared elapsed period is not a locked Historical period inside the run's range",
            ));
        }
        periods.push(row);
    }
    let mut seen_opening = BTreeSet::new();
    let mut routes = Vec::with_capacity(batch.chunks.len());
    let mut opening_fold = BalanceFold::new();
    let mut period_folds: BTreeMap<&str, BalanceFold> = BTreeMap::new();
    for (index, chunk) in batch.chunks.iter().enumerate() {
        let (route, fold) = if selected.contains(&chunk.provenance.source_id) {
            if !seen_opening.insert(chunk.provenance.source_id.as_str()) {
                return Err(usage(
                    "an opening_entries ID identifies more than one source entry",
                    "retain an export with unambiguous journal IDs; opening stock is never selected by a guessed row or date",
                ));
            }
            if chunk.effective_date > run.body.opening_date {
                return Err(usage(
                    "a selected opening entry is dated after the run opening date",
                    "select only opening-stock source entries dated on or before the run's fiscal-year start; elapsed-period activity keeps its original date",
                ));
            }
            (
                SourceRoute {
                    date: run.body.opening_date,
                    period: opening.to_owned(),
                },
                &mut opening_fold,
            )
        } else {
            let matches: Vec<_> = periods
                .iter()
                .filter(|period| {
                    chunk.effective_date >= period.start && chunk.effective_date < period.end
                })
                .collect();
            let [period] = matches.as_slice() else {
                return Err(usage(
                    format!(
                        "source entry {index} is outside the run's declared Historical periods"
                    ),
                    "name opening-stock IDs in opening_entries and include only activity in declared elapsed periods; current-period activity and pre-opening detail need their own native workflow",
                ));
            };
            (
                SourceRoute {
                    date: chunk.effective_date,
                    period: period.code.clone(),
                },
                period_folds.entry(period.code.as_str()).or_default(),
            )
        };
        for leg in &chunk.legs {
            let amount = match leg.side {
                Side::Debit => leg.amount.mantissa,
                Side::Credit => leg
                    .amount
                    .mantissa
                    .checked_neg()
                    .ok_or_else(|| invalid("source credit cannot be negated exactly"))?,
            };
            add_balance(fold, &leg.account_code, leg.amount.unit, amount)?;
        }
        routes.push(route);
    }
    if seen_opening.len() != selected.len() {
        return Err(usage(
            "opening_entries contains an ID absent from the complete source",
            "use each opening-stock source journal ID exactly once; source entry IDs remain private sealed configuration",
        ));
    }
    check_balance(&opening_fold, &run.body.lines, "at the opening")?;
    let mut cumulative = opening_fold;
    for declared in &run.body.periods {
        if let Some(movement) = period_folds.get(declared.period_code.as_str()) {
            for ((account, unit), amount) in movement {
                add_balance(&mut cumulative, account, *unit, *amount)?;
            }
        }
        // A zero-activity period contributes no invented zero-value entry;
        // its independently declared cumulative balance must still tie out.
        check_balance(
            &cumulative,
            &declared.lines,
            &format!("through `{}`", declared.period_code),
        )?;
    }
    Ok(routes)
}

fn route_proposals(
    kind: PackageKind,
    proposals: &mut [EntryPayload],
    routes: &[SourceRoute],
) -> Result<(), Fail> {
    if proposals.len() != routes.len() {
        return Err(invalid("source routing and proposal counts differ"));
    }
    let prefix = match kind {
        PackageKind::OpeningOnly => return Ok(()),
        PackageKind::PeriodBalances => "legacy-period-balances:v1",
        PackageKind::FullDetail => "legacy-full-detail:v1",
    };
    for (index, (proposal, route)) in proposals.iter_mut().zip(routes).enumerate() {
        proposal.effective_date = route.date;
        proposal
            .effective_period
            .as_mut()
            .ok_or_else(|| invalid("source proposal has no period"))?
            .code
            .clone_from(&route.period);
        proposal.idempotency_key = format!("{prefix}:{index}").into_bytes();
    }
    Ok(())
}

fn trial_balance_documents(
    book: &mut Book,
    cap: &Capability,
    run: &Run,
) -> Result<Vec<Document>, Fail> {
    run.body
        .documents()
        .into_iter()
        .map(|oid| full_document(book, cap, oid))
        .collect()
}

fn evidence(source: &Document, trial_balances: &[Document]) -> Vec<EvidenceRef> {
    let mut evidence: Vec<_> = std::iter::once(source)
        .chain(trial_balances)
        .map(|document| document.evidence_ref(1))
        .collect();
    evidence.sort();
    evidence.dedup();
    evidence
}

fn package_tags() -> Result<(u8, u8), Fail> {
    let policy = EvidencePolicy::embedded().map_err(|error| Fail::Internal(error.to_string()))?;
    let kind = policy
        .kind_by_name("Workpaper")
        .ok_or_else(|| Fail::Internal("Workpaper kind is not registered".into()))?
        .tag;
    // Preparation is restricted to a Human capability. The native upload
    // derives this grade again and records that holder's custody; parsing the
    // source does not establish the generation receipt required by Generated.
    let grade =
        fa_journal::upload::upload_grade(&policy, Profile::Human).map_err(BookError::Kernel)?;
    Ok((kind, grade))
}

fn source_replay(
    book: &Book,
    package: &Package,
    batch: &LegacyImportBatch,
    run: &Run,
    period: &str,
    evidence: Vec<EvidenceRef>,
    routes: &[SourceRoute],
) -> Result<(), Fail> {
    let mut fields = VecDeque::new();
    for proposal in &package.proposals {
        for leg in &proposal.legs {
            if let Some(memo) = &leg.memo {
                fields.push_back(memo.clone());
            }
        }
        let EntryOrigin::Migration {
            source_id,
            source_entered_by,
            source_approved_by,
            ..
        } = &proposal.origin
        else {
            return Err(invalid("a package proposal is not a migration"));
        };
        fields.push_back(source_id.clone());
        if let Some(who) = source_entered_by {
            fields.push_back(who.clone());
        }
        if let Some(who) = source_approved_by {
            fields.push_back(who.clone());
        }
        fields.push_back(proposal.description.clone());
    }
    let preparer = package
        .proposals
        .first()
        .ok_or_else(|| invalid("empty package"))?
        .principal_ref;
    let mut expected = batch.to_chunk_proposals_with_sealer(
        book.context(),
        run.vid,
        run.body.opening_date,
        Some(period),
        preparer,
        package.source,
        evidence,
        |text| {
            let retained = fields
                .pop_front()
                .ok_or_else(|| invalid("a source field is missing from the retained proposals"))?;
            if retained.subject_ref().is_some()
                || retained
                    .open(&book.context().seal_key, MAX_REQUEST_BYTES)
                    .map_err(|_| {
                        invalid("a retained private source field cannot be authenticated")
                    })?
                    != text
            {
                return Err(invalid(
                    "retained private provenance differs from the original source",
                ));
            }
            Ok::<_, Fail>(retained)
        },
    )?;
    route_proposals(package.kind, &mut expected, routes)?;
    if !fields.is_empty() || expected != package.proposals {
        return Err(invalid(
            "retained proposal structure differs from the complete source, mapping or run",
        ));
    }
    Ok(())
}

fn recorded_chunks(book: &Book, run: &Run, package: &Package) -> Result<TieOut, Fail> {
    let tie = book.migration_tie_out(run, None)?;
    let expected: BTreeMap<_, _> = package
        .proposals
        .iter()
        .map(|proposal| {
            Ok((
                migration_entry_vid(package.book_id, package.run, &proposal.idempotency_key),
                proposal
                    .proposal_digest()
                    .map_err(|error| invalid(error.to_string()))?,
            ))
        })
        .collect::<Result<_, Fail>>()?;
    for chunk in &tie.chunks {
        if expected.get(&chunk.vid) != Some(&chunk.proposal_digest) {
            return Err(invalid(
                "the run contains a chunk outside this exact package; do not combine regenerated or independently prepared packages",
            ));
        }
    }
    Ok(tie)
}

struct Loaded {
    document: Document,
    package: Package,
    run: Run,
    batch: LegacyImportBatch,
    period: String,
    tie: TieOut,
}

fn retained_package(
    book: &mut Book,
    cap: &Capability,
    run: &Run,
    config: &str,
) -> Result<Option<Loaded>, Fail> {
    let (kind, grade) = package_tags()?;
    // Native inventory is ordered by original intake sequence and OID. The
    // first complete package fixes this run's approval material permanently,
    // including when preparation's response was lost before any chunk staged.
    for summary in book.documents(None)?? {
        if summary.kind != kind
            || summary.grade != grade
            || !matches!(
                summary.mime.as_str(),
                PACKAGE_MIME | PERIOD_BALANCES_MIME | FULL_DETAIL_MIME
            )
        {
            continue;
        }
        let document = full_document(book, cap, summary.oid)?;
        let package = Package::decode(&document.bytes)?;
        if package.run != run.vid {
            continue;
        }
        let loaded = load_package(book, cap, summary.oid)?;
        if loaded.document.retrieved_by != cap.holder() {
            return Err(usage(
                "this run's retained package was prepared by a different principal",
                "inspect or stage the original package with its independently approved proposals; use a new run for a different preparer",
            ));
        }
        // load_package has already reauthorized the complete source and
        // replayed the exact proposals before this private configuration opens.
        let retained = loaded
            .package
            .request
            .open(&book.context().seal_key, MAX_REQUEST_BYTES)
            .map_err(|_| invalid("sealed mapping configuration cannot be authenticated"))?;
        if retained != config {
            return Err(usage(
                "this run already has a retained package with different source or mapping",
                "resume with the original package OID; open a new independently declared run for changed source, mapping, or parser configuration",
            ));
        }
        return Ok(Some(loaded));
    }
    Ok(None)
}

fn load_package(book: &mut Book, cap: &Capability, selected: Oid) -> Result<Loaded, Fail> {
    let document = full_document(book, cap, selected)?;
    let (kind, grade) = package_tags()?;
    if document.oid() != selected
        || document.kind != kind
        || document.grade != grade
        || !matches!(
            document.mime.as_str(),
            PACKAGE_MIME | PERIOD_BALANCES_MIME | FULL_DETAIL_MIME
        )
    {
        return Err(invalid(
            "selected Document is not a legacy import Workpaper retained by a Human upload",
        ));
    }
    let package = Package::decode(&document.bytes)?;
    if document.mime != package.kind.mime() {
        return Err(invalid("package media type differs from its encoded mode"));
    }
    if package.book_id != book.context().book_id {
        return Err(invalid("package belongs to another book"));
    }
    if package
        .proposals
        .iter()
        .any(|proposal| proposal.principal_ref != document.retrieved_by)
    {
        return Err(invalid(
            "proposal preparer differs from the original package uploader",
        ));
    }
    // Authorize the original source before opening the sealed mapping. A
    // readable Workpaper never grants access to a governed source Document.
    let source = full_document(book, cap, package.source)?;
    if source.doc_commit() != package.source_commit {
        return Err(invalid(
            "retained source commitment differs from the package",
        ));
    }
    let run = load_run(book, package.run)?;
    if package.kind != PackageKind::for_run(&run) {
        return Err(invalid("package mode differs from the migration run"));
    }
    if run.body.digest().map_err(BookError::Kernel)? != package.run_body_digest {
        return Err(invalid("migration run body differs from the package"));
    }
    let trial_balances = trial_balance_documents(book, cap, &run)?;
    let config = package
        .request
        .open(&book.context().seal_key, MAX_REQUEST_BYTES)
        .map_err(|_| invalid("sealed mapping configuration cannot be authenticated"))?;
    let mut request = ImportRequest::parse(package.book_id, &config)?;
    if request.run != package.run
        || request.source != package.source
        || package.request.subject_ref().is_some()
    {
        return Err(invalid(
            "mapping configuration does not bind the selected run and source",
        ));
    }
    let batch = parse_source(book, &mut request, &run, &source)?;
    let period = opening_period(book, &run, false)?;
    let routes = source_routes(book, &request, &run, &batch, &period)?;
    source_replay(
        book,
        &package,
        &batch,
        &run,
        &period,
        evidence(&source, &trial_balances),
        &routes,
    )?;
    let tie = recorded_chunks(book, &run, &package)?;
    Ok(Loaded {
        document,
        package,
        run,
        batch,
        period,
        tie,
    })
}

fn side_name(side: Side) -> &'static str {
    match side {
        Side::Debit => "debit",
        Side::Credit => "credit",
    }
}

fn fields(book: &Book, loaded: &Loaded) -> Result<Vec<(&'static str, Json)>, Fail> {
    let chunks = loaded
        .package
        .proposals
        .iter()
        .enumerate()
        .map(|(index, proposal)| {
            let source = loaded
                .batch
                .chunks
                .get(index)
                .ok_or_else(|| invalid("missing parsed chunk"))?;
            let legs = proposal
                .legs
                .iter()
                .zip(&source.legs)
                .enumerate()
                .map(|(index, (leg, source))| {
                    Ok(obj(vec![
                        ("index", Json::Int(index as i128)),
                        ("account", s(&source.account_code)),
                        ("side", s(side_name(leg.side))),
                        (
                            "amount",
                            s(render_amount(leg.amount, &book.context().units)?),
                        ),
                    ]))
                })
                .collect::<Result<Vec<_>, Fail>>()?;
            let vid = migration_entry_vid(
                loaded.package.book_id,
                loaded.run.vid,
                &proposal.idempotency_key,
            );
            let mut fields = vec![
                ("index", Json::Int(index as i128)),
                ("entry_vid", s(format!("{:032x}", vid.0))),
                (
                    "proposal_digest",
                    s(hex(&proposal
                        .proposal_digest()
                        .map_err(|error| invalid(error.to_string()))?)),
                ),
                ("effective_date", s(proposal.effective_date.render())),
                ("leg_count", Json::Int(proposal.legs.len() as i128)),
                ("legs", Json::Arr(legs)),
            ];
            fields.push((
                "document_date",
                proposal
                    .document_date
                    .map_or(Json::Null, |date| s(date.render())),
            ));
            fields.push((
                "effective_period",
                if loaded.package.kind != PackageKind::OpeningOnly {
                    s(&proposal
                        .effective_period
                        .as_ref()
                        .ok_or_else(|| invalid("retained period proposal has no period"))?
                        .code)
                } else {
                    Json::Null
                },
            ));
            fields.push((
                "counts_after_finalize",
                if loaded.package.kind == PackageKind::FullDetail {
                    Json::Bool(
                        loaded.run.state != RunState::Abandoned
                            && (loaded.run.body.sole_opening_source
                                || proposal.effective_date >= loaded.run.body.opening_date),
                    )
                } else {
                    Json::Null
                },
            ));
            fields.push((
                "recorded_at",
                loaded
                    .tie
                    .chunks
                    .iter()
                    .find(|chunk| chunk.vid == vid)
                    .map_or(Json::Null, |chunk| {
                        Json::Int(i128::from(chunk.recorded_at.0))
                    }),
            ));
            Ok(obj(fields))
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let mut fields = vec![
        ("package_oid", s(hex(&loaded.document.oid().0))),
        ("package_commit", s(hex(&loaded.document.doc_commit()))),
        ("run_vid", s(format!("{:032x}", loaded.run.vid.0))),
        ("run_key", s(&loaded.run.body.run_key)),
        ("run_body_digest", s(hex(&loaded.package.run_body_digest))),
        ("source_oid", s(hex(&loaded.package.source.0))),
        ("source_commit", s(hex(&loaded.package.source_commit))),
        ("format", s(format_name(loaded.batch.format))),
        ("mode", s(loaded.package.kind.mode_name())),
        ("opening_date", s(loaded.run.body.opening_date.render())),
        ("opening_period", s(&loaded.period)),
        ("row_count", Json::Int(loaded.batch.row_count as i128)),
        (
            "chunk_count",
            Json::Int(loaded.package.proposals.len() as i128),
        ),
        ("recorded_count", Json::Int(loaded.tie.chunks.len() as i128)),
        ("run_state", s(loaded.run.state.name())),
        ("ties_out", Json::Bool(loaded.tie.mismatches.is_empty())),
        ("chunks", Json::Arr(chunks)),
    ];
    fields.push((
        "sole_opening_source",
        if loaded.package.kind == PackageKind::FullDetail {
            Json::Bool(loaded.run.body.sole_opening_source)
        } else {
            Json::Null
        },
    ));
    Ok(fields)
}

fn review_text(book: &Book, loaded: &Loaded) -> Result<String, Fail> {
    let mut lines = Vec::new();
    for (index, (proposal, source)) in loaded
        .package
        .proposals
        .iter()
        .zip(&loaded.batch.chunks)
        .enumerate()
    {
        lines.push(format!(
            "chunk {index}: proposal {}; effective {}{}; source date {}",
            hex(&proposal
                .proposal_digest()
                .map_err(|error| invalid(error.to_string()))?),
            proposal.effective_date.render(),
            if loaded.package.kind != PackageKind::OpeningOnly {
                format!(
                    " in {}",
                    proposal
                        .effective_period
                        .as_ref()
                        .ok_or_else(|| invalid("retained period proposal has no period"))?
                        .code
                )
            } else {
                String::new()
            },
            source.effective_date.render()
        ));
        if loaded.package.kind == PackageKind::FullDetail {
            if loaded.run.state == RunState::Abandoned {
                lines.push("  abandoned run; this chunk remains permanently invisible to balances and open items".into());
            } else if !loaded.run.body.sole_opening_source
                && proposal.effective_date < loaded.run.body.opening_date
            {
                lines.push("  retained historical detail; excluded from balances and open items after finalization".into());
            }
        }
        for (leg, source) in proposal.legs.iter().zip(&source.legs) {
            lines.push(format!(
                "  {} {} {}",
                side_name(leg.side),
                source.account_code,
                render_amount(leg.amount, &book.context().units)?
            ));
        }
    }
    Ok(lines.join("\n"))
}

pub(crate) fn import_cmd(ctx: &mut Ctx<'_>, args: &Args) -> Result<(), Fail> {
    let action = options(args)?;
    let writing = action != "show";
    let cap = capability(ctx, args, writing)?;
    let mut book = ctx
        .books
        .open_admitted(args, |book| admit_book(book, &cap, writing))?;
    if action == "prepare" {
        let path = args.require("--intent", "import.json or -")?;
        let bytes =
            crate::intake::read_document_with_limit(&ctx.files, path, MAX_REQUEST_BYTES as u64)?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| usage("legacy import intent must be UTF-8 JSON", EXAMPLE))?;
        let mut request = ImportRequest::parse(book.context().book_id, text)?;
        let run = load_run(&book, request.run)?;
        let tie = book.migration_tie_out(&run, None)?;
        let source = full_document(&mut book, &cap, request.source)?;
        let trial_balances = trial_balance_documents(&mut book, &cap, &run)?;
        let batch = parse_source(&book, &mut request, &run, &source)?;
        let config = request.canonical_text();
        if config.len() > MAX_REQUEST_BYTES {
            return Err(usage(
                "normalized import configuration exceeds its 1 MiB bound",
                "reduce the explicit mapping and split the source into separate complete runs",
            ));
        }
        let loaded = if let Some(loaded) = retained_package(&mut book, &cap, &run, &config)? {
            loaded
        } else {
            if run.state != RunState::Open {
                return Err(usage(
                    "first preparation requires an Open migration run",
                    "use the retained package to inspect or retry an existing run, or open a new independently declared run",
                ));
            }
            if !tie.chunks.is_empty() {
                return Err(usage(
                    "this run already has staged chunks without this import's retained package",
                    "resume with the original native migration plans; use a new empty run for a legacy source import",
                ));
            }
            let period = opening_period(&book, &run, true)?;
            let routes = source_routes(&book, &request, &run, &batch, &period)?;
            let kind = PackageKind::for_run(&run);
            let mut proposals = batch.to_chunk_proposals_with_sealer(
                book.context(),
                run.vid,
                run.body.opening_date,
                Some(&period),
                cap.holder(),
                request.source,
                evidence(&source, &trial_balances),
                |text| book.seal_text(text).map_err(Fail::Book),
            )?;
            route_proposals(kind, &mut proposals, &routes)?;
            let package = Package {
                kind,
                book_id: book.context().book_id,
                run: run.vid,
                run_body_digest: run.body.digest().map_err(BookError::Kernel)?,
                source: source.oid(),
                source_commit: source.doc_commit(),
                request: book.seal_text(&config)?,
                proposals,
            };
            let (kind, grade) = package_tags()?;
            let document = Document {
                book_id: book.context().book_id,
                kind,
                mime: package.kind.mime().into(),
                grade,
                retrieved_by: cap.holder(),
                bytes: package.encode()?,
            };
            Loaded {
                document,
                package,
                run,
                batch,
                period,
                tie,
            }
        };
        let mut output = fields(&book, &loaded)?;
        let review = review_text(&book, &loaded)?;
        if let Some(path) = args.flag("--plan-out") {
            write_post_plan(&ctx.files, path, &loaded.document.bytes)?;
        }
        // The package retains the admitted operator's custody, not a verified
        // generation claim. The native upload derives grade and uploader from
        // the capability and retains its current-authority witnesses through
        // publication. Source replay and independent approvals remain separate.
        admit_book(&book, &cap, true)?;
        let added = book.upload_document(
            &cap,
            fa_journal::UploadRequest {
                kind: loaded.document.kind,
                mime: loaded.document.mime,
                bytes: loaded.document.bytes,
                asserted_grade: Some(loaded.document.grade),
            },
        )??;
        output.push(("recorded_at", Json::Int(i128::from(added.recorded_at.0))));
        output.push(("already_recorded", Json::Bool(added.already_recorded)));
        output.push(("plan", args.flag("--plan-out").map_or(Json::Null, s)));
        ctx.out.at_book(&book)?;
        ctx.out.event("migration_import_prepared", output, &format!(
            "prepared {} exact {} chunks for `{}`; package D:{}; source ties to every declared trial balance; collect independent approvals for each proposal digest before staging\n{review}",
            loaded.package.proposals.len(), loaded.package.kind.mode_name(), loaded.run.body.run_key, hex(&added.oid.0),
        ));
        return Ok(());
    }
    let package_oid = oid(args.require("--package", "D:<64-hex-oid>")?, "--package")?;
    let loaded = load_package(&mut book, &cap, package_oid)?;
    if action == "show" {
        ctx.out.at_book(&book)?;
        let review = review_text(&book, &loaded)?;
        ctx.out.event("migration_import_package", fields(&book, &loaded)?, &format!(
            "legacy {} package D:{} for `{}`: {}/{} exact chunks staged; run {}; finalization remains an independently approved native transition\n{review}",
            loaded.package.kind.mode_name(), hex(&package_oid.0), loaded.run.body.run_key, loaded.tie.chunks.len(), loaded.package.proposals.len(), loaded.run.state.name(),
        ));
        return Ok(());
    }
    let index = args
        .require("--chunk", "zero-based package chunk index")?
        .parse::<usize>()
        .map_err(|_| usage("--chunk needs a nonnegative zero-based index", EXAMPLE))?;
    let proposal = loaded
        .package
        .proposals
        .get(index)
        .ok_or_else(|| {
            usage(
                "--chunk is outside this package",
                "inspect --action show and select an exact listed chunk index",
            )
        })?
        .clone();
    let digest = proposal
        .proposal_digest()
        .map_err(|error| invalid(error.to_string()))?;
    let approvals = args
        .flag_all("--approval")
        .into_iter()
        .map(|text| {
            let text = text.strip_prefix("A:").unwrap_or(text);
            Ok(ApprovalRef {
                approval_vid: VId(u128::from_be_bytes(fixed_hex(text, "--approval")?)),
                approved_digest: digest,
            })
        })
        .collect::<Result<Vec<_>, Fail>>()?;
    let posted = book.post(PostRequest {
        proposal,
        approvals,
        plan_certificate: None,
        capability: cap,
    })??;
    let run = load_run(&book, loaded.run.vid)?;
    let tie = recorded_chunks(&book, &run, &loaded.package)?;
    let ready = run.state == RunState::Open
        && tie.chunks.len() == loaded.package.proposals.len()
        && tie.mismatches.is_empty();
    let already_recorded = matches!(posted, Posted::AlreadyRecorded { .. });
    ctx.out.at_book(&book)?;
    ctx.out.event("migration_import_staged", vec![
        ("package_oid", s(hex(&package_oid.0))), ("run_vid", s(format!("{:032x}", run.vid.0))),
        ("chunk_index", Json::Int(index as i128)), ("entry_vid", s(format!("{:032x}", posted.entry_ref().vid.0))),
        ("proposal_digest", s(hex(&digest))), ("recorded_at", Json::Int(i128::from(posted.recorded_at().0))),
        ("already_recorded", Json::Bool(already_recorded)), ("run_state", s(run.state.name())),
        ("recorded_count", Json::Int(tie.chunks.len() as i128)), ("chunk_count", Json::Int(loaded.package.proposals.len() as i128)),
        ("ready_to_finalize", Json::Bool(ready)),
    ], &format!("{} exact chunk {index} for `{}`; {}/{} staged; {}",
        if already_recorded { "already recorded" } else { "staged" }, run.body.run_key,
        tie.chunks.len(), loaded.package.proposals.len(),
        if ready { "prepare and independently approve `fa migrate finalize` to activate the complete run" } else { "retain this package to resume; only native finalization activates an Open run" },
    ));
    Ok(())
}
