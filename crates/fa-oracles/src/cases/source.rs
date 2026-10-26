//! `sources.toml`: one `[[source]]` row per retrieved document
//! (docs/FORENSIC_CASE_STUDIES_PLAN.md §4.1, §2.2).

use fa_registry::toml::{Document, Table, Value as TomlValue};

use super::error::{LoadError, LoadErrorKind};
use super::fields::{Row, is_date, is_sha256_hex};
use super::rows::row_line;

closed_set! {
    /// How the bytes were obtained (§4.1).
    RetrievalRoute {
        Original => "original",
        ArchiveCapture => "archive_capture",
        ThirdPartyCopy => "third_party_copy",
        ReRender => "re_render",
    }
}

closed_set! {
    /// The retrieved file's format (§4.1).
    SourceFormat {
        Pdf => "pdf",
        Htm => "htm",
        Txt => "txt",
        Xml => "xml",
        Json => "json",
    }
}

closed_set! {
    /// Why the source may be quoted or excerpted (§1.3, §4.1).
    RedistributionBasis {
        SecFiling => "public-record/sec-filing",
        Court => "public-record/court",
        GovernmentWork => "government-work",
        EdgarExhibit => "company-commissioned/edgar-exhibit",
        ThirdPartyHosted => "third-party-hosted",
    }
}

closed_set! {
    /// What kind of assertion the source makes; rendered into every claim
    /// sentence resting on it (§2.2, K-ASSERT).
    AssertionStatus {
        Allegation => "allegation",
        Charge => "charge",
        InvestigativeFinding => "investigative_finding",
        TrusteeComputation => "trustee_computation",
        FilerAudited => "filer_audited",
        FilerReviewed => "filer_reviewed",
        FilerUnaudited => "filer_unaudited",
        FilerNotFromAuditedStatements => "filer_not_from_audited_statements",
        CourtRuling => "court_ruling",
    }
}

impl AssertionStatus {
    /// Whether the source is a filer's own statement, the only kind that
    /// carries an `assurance` (§4.1).
    #[must_use]
    pub const fn is_filer_statement(self) -> bool {
        matches!(
            self,
            Self::FilerAudited
                | Self::FilerReviewed
                | Self::FilerUnaudited
                | Self::FilerNotFromAuditedStatements
        )
    }
}

closed_set! {
    /// A filer statement's assurance, from its audit report, review report
    /// or legend (§2.2, §4.1). `NotApplicable` is the empty string a row
    /// that is not a filer statement may carry.
    Assurance {
        Audited => "audited",
        Reviewed => "reviewed",
        Unaudited => "unaudited",
        NotFromAudited => "not-from-audited",
        NotApplicable => "",
    }
}

closed_set! {
    /// How a fact's anchor locates its excerpt (§4.1).
    AnchorKind {
        Page => "page",
        Line => "line",
        TableCell => "table_cell",
        Xbrl => "xbrl",
        Paragraph => "paragraph",
        Exhibit => "exhibit",
    }
}

impl AnchorKind {
    /// Prose anchors bind by sentence alignment; table cells, XBRL facts and
    /// exhibits bind by exact value (§4.1).
    #[must_use]
    pub const fn is_prose(self) -> bool {
        matches!(self, Self::Page | Self::Line | Self::Paragraph)
    }
}

closed_set! {
    /// Whether facts may cite the source (§4.1: only `OK` rows).
    SourceStatus {
        Ok => "OK",
        Blocked => "BLOCKED",
    }
}

/// One `[[source]]` row.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub id: String,
    pub title: String,
    pub publisher: String,
    pub original_url: String,
    pub archive_url: Option<String>,
    pub retrieval_route: RetrievalRoute,
    pub original_hash_compared: bool,
    pub retrieved_utc: String,
    pub sha256: String,
    pub format: SourceFormat,
    /// Tool, version and SHA-256 of the extracted text, when the anchor
    /// scheme needs text.
    pub extraction: Option<Vec<String>>,
    pub redistribution_basis: RedistributionBasis,
    pub assertion_status: AssertionStatus,
    pub assurance: Option<Assurance>,
    pub assurance_fact: Option<String>,
    pub anchor_scheme: Vec<AnchorKind>,
    pub status: SourceStatus,
    pub status_reason: Option<String>,
    pub notes: Option<String>,
    /// The filing or publication date (`YYYY-MM-DD`), or empty.
    pub filed_on: Option<String>,
    /// Source ids whose figures this filing restates (K-VINTAGE).
    pub restates: Option<Vec<String>>,
    /// The row's header line.
    pub line: Option<usize>,
}

pub(crate) fn parse_rows(
    file: &str,
    text: &str,
    rows: &[Table],
    errs: &mut Vec<LoadError>,
) -> Vec<Source> {
    let mut out = Vec::with_capacity(rows.len());
    for (i, table) in rows.iter().enumerate() {
        let mut r = Row::new(file, row_line(text, "source", i), table);
        let id = r.req_str("id", errs);
        let title = r.req_str("title", errs);
        let publisher = r.req_str("publisher", errs);
        let original_url = r.req_str("original_url", errs);
        let archive_url = r.opt_str("archive_url", errs);
        let route_raw = r.req_str("retrieval_route", errs);
        let original_hash_compared = r.req_bool("original_hash_compared", errs);
        let retrieved_utc = r.req_str("retrieved_utc", errs);
        let sha256 = r.req_str("sha256", errs);
        let format_raw = r.req_str("format", errs);
        let extraction = r.opt_strs("extraction", errs);
        let basis_raw = r.req_str("redistribution_basis", errs);
        let status_raw = r.req_str("assertion_status", errs);
        let assurance_raw = r.opt_str("assurance", errs);
        let assurance_fact = r.opt_str("assurance_fact", errs);
        let scheme_raw = r.req_strs("anchor_scheme", errs);
        let src_status_raw = r.req_str("status", errs);
        let status_reason = r.opt_str("status_reason", errs);
        let notes = r.opt_str("notes", errs);
        let filed_on = r.opt_str("filed_on", errs);
        let restates = r.opt_strs("restates", errs);
        r.finish(&[], "", errs);

        let retrieval_route = closed(
            &r,
            "retrieval_route",
            &route_raw,
            RetrievalRoute::parse,
            errs,
        )
        .unwrap_or(RetrievalRoute::Original);
        let format = closed(&r, "format", &format_raw, SourceFormat::parse, errs)
            .unwrap_or(SourceFormat::Pdf);
        let redistribution_basis = closed(
            &r,
            "redistribution_basis",
            &basis_raw,
            RedistributionBasis::parse,
            errs,
        )
        .unwrap_or(RedistributionBasis::SecFiling);
        let assertion_status = closed(
            &r,
            "assertion_status",
            &status_raw,
            AssertionStatus::parse,
            errs,
        )
        .unwrap_or(AssertionStatus::Allegation);
        let status = closed(&r, "status", &src_status_raw, SourceStatus::parse, errs)
            .unwrap_or(SourceStatus::Blocked);
        let assurance = assurance_raw
            .as_deref()
            .and_then(|a| closed(&r, "assurance", a, Assurance::parse, errs));
        let mut anchor_scheme = Vec::with_capacity(scheme_raw.len());
        for kind in &scheme_raw {
            if let Some(k) = closed(&r, "anchor_scheme", kind, AnchorKind::parse, errs) {
                anchor_scheme.push(k);
            }
        }
        if !sha256.is_empty() && !is_sha256_hex(&sha256) {
            errs.push(r.err(
                LoadErrorKind::NotSha256Hex,
                "`sha256` must be 64 lower-case hex characters",
            ));
        }
        if let Some(ext) = &extraction {
            if ext.len() != 3 {
                errs.push(r.err(
                    LoadErrorKind::WrongType,
                    "`extraction` is [tool, version, SHA-256 of the extracted text]",
                ));
            } else if !is_sha256_hex(&ext[2]) {
                errs.push(r.err(
                    LoadErrorKind::NotSha256Hex,
                    "`extraction`'s third element must be 64 lower-case hex characters",
                ));
            }
        }
        if status == SourceStatus::Blocked && status_reason.as_deref().is_none_or(str::is_empty) {
            errs.push(r.err(
                LoadErrorKind::MissingField,
                "a BLOCKED source needs `status_reason`",
            ));
        }
        if let Some(a) = assurance
            && a != Assurance::NotApplicable
            && !assertion_status.is_filer_statement()
        {
            errs.push(r.err(
                LoadErrorKind::UnknownValue,
                format!(
                    "`assurance = \"{}\"` on a row that is not a filer statement",
                    a.as_str()
                ),
            ));
        }
        if assurance_fact.is_some() && assurance.is_none_or(|a| a == Assurance::NotApplicable) {
            errs.push(r.err(
                LoadErrorKind::MissingField,
                "`assurance_fact` without an `assurance`",
            ));
        }
        if let Some(d) = &filed_on
            && !d.is_empty()
            && !is_date(d)
        {
            errs.push(r.err(
                LoadErrorKind::WrongType,
                "`filed_on` must be YYYY-MM-DD or empty",
            ));
        }
        let line = r.line();
        out.push(Source {
            id,
            title,
            publisher,
            original_url,
            archive_url,
            retrieval_route,
            original_hash_compared,
            retrieved_utc,
            sha256,
            format,
            extraction,
            redistribution_basis,
            assertion_status,
            assurance,
            assurance_fact,
            anchor_scheme,
            status,
            status_reason,
            notes,
            filed_on,
            restates,
            line,
        });
    }
    out
}

/// Parses a closed-set value, refusing an unknown one as `UnknownValue`.
pub(crate) fn closed<T>(
    r: &Row<'_>,
    key: &str,
    raw: &str,
    parse: fn(&str) -> Option<T>,
    errs: &mut Vec<LoadError>,
) -> Option<T> {
    let parsed = parse(raw);
    if parsed.is_none() && !raw.is_empty() {
        errs.push(r.err(
            LoadErrorKind::UnknownValue,
            format!("`{key} = \"{raw}\"` is outside its closed set"),
        ));
    }
    parsed
}

impl Source {
    /// The row as the TOML subset's table (the canonical-bytes round trip).
    #[must_use]
    pub fn to_table(&self) -> Table {
        let mut t = Table::new();
        put(&mut t, "id", &self.id);
        put(&mut t, "title", &self.title);
        put(&mut t, "publisher", &self.publisher);
        put(&mut t, "original_url", &self.original_url);
        put_opt(&mut t, "archive_url", self.archive_url.as_deref());
        put(&mut t, "retrieval_route", self.retrieval_route.as_str());
        t.insert(
            "original_hash_compared".into(),
            TomlValue::Bool(self.original_hash_compared),
        );
        put(&mut t, "retrieved_utc", &self.retrieved_utc);
        put(&mut t, "sha256", &self.sha256);
        put(&mut t, "format", self.format.as_str());
        put_strs(&mut t, "extraction", self.extraction.as_deref());
        put(
            &mut t,
            "redistribution_basis",
            self.redistribution_basis.as_str(),
        );
        put(&mut t, "assertion_status", self.assertion_status.as_str());
        put_opt(&mut t, "assurance", self.assurance.map(Assurance::as_str));
        put_opt(&mut t, "assurance_fact", self.assurance_fact.as_deref());
        let scheme: Vec<String> = self
            .anchor_scheme
            .iter()
            .map(|k| k.as_str().to_string())
            .collect();
        put_strs(&mut t, "anchor_scheme", Some(&scheme));
        put(&mut t, "status", self.status.as_str());
        put_opt(&mut t, "status_reason", self.status_reason.as_deref());
        put_opt(&mut t, "notes", self.notes.as_deref());
        put_opt(&mut t, "filed_on", self.filed_on.as_deref());
        put_strs(&mut t, "restates", self.restates.as_deref());
        t
    }
}

/// `sources.toml` as a document.
#[must_use]
pub fn to_document(sources: &[Source]) -> Document {
    let mut doc = Document::default();
    if !sources.is_empty() {
        doc.arrays.insert(
            "source".into(),
            sources.iter().map(Source::to_table).collect(),
        );
    }
    doc
}

pub(crate) fn put(t: &mut Table, key: &str, value: &str) {
    t.insert(key.into(), TomlValue::Str(value.to_string()));
}

pub(crate) fn put_opt(t: &mut Table, key: &str, value: Option<&str>) {
    if let Some(v) = value {
        put(t, key, v);
    }
}

pub(crate) fn put_strs(t: &mut Table, key: &str, value: Option<&[String]>) {
    if let Some(items) = value {
        t.insert(
            key.into(),
            TomlValue::Array(items.iter().map(|s| TomlValue::Str(s.clone())).collect()),
        );
    }
}
