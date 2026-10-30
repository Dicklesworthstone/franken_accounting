//! Immutable source registries for retained native trial balances, open items,
//! statements and balance explanations.
//!
//! The epoch archives source text, not executable code or an authorization grant.
//! Its semantic closure is the digest the original certificate already binds.
//! The root and any object fragments publish in the certificate's transaction;
//! neither certification nor replay creates a write. Older unarchived certificates
//! keep their existing exact-environment replay contract.
//!
//! This first interpreter accepts unchanged account/entry semantics and the
//! book's immutable unit definitions. Foundation pins are retained provenance:
//! a changed pin is permitted only after all native read certificates still
//! replay and the complete historical accounting fold reproduces the output.
//! One-book consolidation additionally retains account-role and rounding
//! sources, plus FX laws for functional v7. Those arithmetic and role meanings
//! must match this interpreter exactly; archiving never activates old policy.
//! Other law-dependent selectors keep their existing stricter contract.

use super::*;
use fa_journal::object::{self, ObjectKind};
use fa_journal::rows::{prop, scalar_bytes};
use fa_model::domain_digest;
use fa_registry::toml::{Document, Value};
use fgdb::{VertexRow, WriteBatch, WriteTxn};
use fgdb_types::CanonicalScalar;

const FORMAT: &[u8] = b"fa:report-registry-epoch:v1";
const NAMES: [&str; 4] = ["account_types", "entry_classes", "units", "foundations"];
const EXPLANATION_NAMES: [&str; 5] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "reason_codes",
];
const CONSOLIDATION_NAMES: [&str; 6] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "account_roles",
    "rounding_laws",
];
const FUNCTIONAL_CONSOLIDATION_NAMES: [&str; 7] = [
    "account_types",
    "entry_classes",
    "units",
    "foundations",
    "account_roles",
    "fx_laws",
    "rounding_laws",
];
const MAX_SOURCE_BYTES: usize = 1024 * 1024;
const MAX_EPOCH_BYTES: usize = 7 * MAX_SOURCE_BYTES + 1024;
// Source transcripts share the existing certificate-maintenance storage class,
// like plan certificates. The epoch kind, body format and identity domain
// distinguish them from report artifacts without changing genesis symbols.
const STORAGE_LABEL: fgdb_delta_types::LabelId = label::CERTIFICATE;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Epoch {
    book_id: Id128,
    closure: [u8; 32],
    sources: Vec<(String, String)>,
}

fn unavailable(why: impl Into<String>) -> Refusal {
    Refusal::new(
        code::CERTIFICATE_REGISTRY_UNAVAILABLE,
        exit::ENVIRONMENT,
        why,
        "plan §13.6 / fa-vdc (retained registry epochs require a supported semantic interpreter)",
        "preserve the certificate and its RegistryEpoch; use an executable supporting that epoch's format and accounting semantics",
    )
}

pub(crate) fn supports(selection: &ReportSelection) -> bool {
    matches!(
        selection,
        ReportSelection::TrialBalance(_)
            | ReportSelection::OpenItems { .. }
            | ReportSelection::Statement(_)
            | ReportSelection::ExplainBalance { .. }
            | ReportSelection::Consolidation { .. }
            | ReportSelection::FunctionalConsolidation { .. }
    )
}

fn document(name: &str, text: &str) -> Result<Document, Refusal> {
    let doc = fa_registry::toml::parse(text)
        .map_err(|error| unavailable(format!("registry epoch {name} cannot be parsed: {error}")))?;
    if doc.root.get("schema_version").and_then(Value::as_int) != Some(1) {
        return Err(unavailable(format!(
            "registry epoch {name} requires an unsupported schema major; this interpreter accepts schema_version = 1"
        )));
    }
    Ok(doc)
}

impl Epoch {
    fn new(book_id: Id128, sources: Vec<(String, String)>) -> Result<Self, Refusal> {
        let names = sources
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        if names != NAMES
            && names != EXPLANATION_NAMES
            && names != CONSOLIDATION_NAMES
            && names != FUNCTIONAL_CONSOLIDATION_NAMES
            || sources
                .iter()
                .any(|(_, text)| text.len() > MAX_SOURCE_BYTES)
        {
            return Err(invalid(
                "a report epoch requires its exact bounded four-source native, five-source explanation, six-source consolidation or seven-source functional consolidation profile",
            ));
        }
        let sources_ref = sources
            .iter()
            .map(|(name, text)| (name.as_str(), text.as_str()))
            .collect::<Vec<_>>();
        let closure = canonical_closure(b"fa:report-registry-closure:v2", &sources_ref)?;
        Ok(Self {
            book_id,
            closure,
            sources,
        })
    }

    fn current(book_id: Id128) -> Result<Self, Refusal> {
        Self::new(
            book_id,
            REPORT_REGISTRIES
                .iter()
                .map(|(name, text)| ((*name).into(), (*text).into()))
                .collect(),
        )
    }

    fn for_selection(book_id: Id128, selection: &ReportSelection) -> Result<Self, Refusal> {
        if !matches!(
            selection,
            ReportSelection::ExplainBalance { .. }
                | ReportSelection::Consolidation { .. }
                | ReportSelection::FunctionalConsolidation { .. }
        ) {
            return Self::current(book_id);
        }
        Self::new(
            book_id,
            report_registries(selection)
                .into_iter()
                .map(|(name, text)| (name.into(), text.into()))
                .collect(),
        )
    }

    /// A valid epoch for another report cannot erase this report's additional
    /// registry obligation, even when a caller reseals the certificate.
    fn admit_for(
        &self,
        selection: &ReportSelection,
        units: &fa_money::UnitRegistry,
    ) -> Result<(), Refusal> {
        let expected = report_registries(selection);
        if self
            .sources
            .iter()
            .map(|(name, _)| name.as_str())
            .ne(expected.iter().map(|(name, _)| *name))
        {
            return Err(unavailable(
                "the retained registry profile does not match this report's selector",
            ));
        }
        self.admit(units)
    }

    fn encode(&self) -> Result<Vec<u8>, Refusal> {
        let mut writer = Writer::new();
        writer
            .fixed(FORMAT)
            .fixed(&self.book_id.0)
            .fixed(&self.closure)
            .list(&self.sources, |writer, (name, text)| {
                writer.str(name).str(text);
            });
        writer
            .finish()
            .map_err(|error| invalid(format!("cannot encode registry epoch: {error}")))
    }

    fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EPOCH_BYTES {
            return Err(invalid("registry epoch exceeds its 7 MiB source budget"));
        }
        let mut reader = Reader::new(bytes);
        let bad = |error| invalid(format!("malformed registry epoch: {error}"));
        if reader
            .fixed::<{ FORMAT.len() }>("registry epoch format")
            .map_err(bad)?
            != FORMAT
        {
            return Err(unavailable("unsupported registry epoch format major"));
        }
        let book_id = Id128(reader.fixed("registry epoch book").map_err(bad)?);
        let closure = reader.fixed("registry epoch closure").map_err(bad)?;
        let count = reader
            .count(FUNCTIONAL_CONSOLIDATION_NAMES.len(), "registry sources")
            .map_err(bad)?;
        let mut sources = Vec::with_capacity(count);
        for _ in 0..count {
            let name = reader.str(64, "registry name").map_err(bad)?.to_string();
            let text = reader
                .str(MAX_SOURCE_BYTES, "registry source")
                .map_err(bad)?
                .to_string();
            sources.push((name, text));
        }
        reader.finish().map_err(bad)?;
        let epoch = Self::new(book_id, sources)?;
        if epoch.closure != closure || epoch.encode()? != bytes {
            return Err(invalid(
                "registry epoch source texts do not reproduce their canonical closure",
            ));
        }
        Ok(epoch)
    }

    /// Validate the captured meanings, not just the certificate's hash. Native
    /// folds do not consult the foundation provenance text. All account-type
    /// and entry-class fields must match the interpreter's exact vocabulary.
    /// The book's unit table is independently authenticated by native replay.
    fn admit(&self, units: &fa_money::UnitRegistry) -> Result<(), Refusal> {
        for (index, (name, text)) in self.sources.iter().enumerate() {
            let archived = document(name, text)?;
            if index < 2 {
                let supported = document(name, REPORT_REGISTRIES[index].1)?;
                if archived != supported {
                    return Err(unavailable(format!(
                        "registry epoch {name} differs from this interpreter's supported accounting semantics"
                    )));
                }
            }
            let exact = match name.as_str() {
                "account_roles" => Some(include_str!("../../../../registries/account_roles.toml")),
                "rounding_laws" => Some(include_str!("../../../../registries/rounding_laws.toml")),
                "fx_laws" => Some(include_str!("../../../../registries/fx_laws.toml")),
                _ => None,
            };
            if let Some(text) = exact
                && archived != document(name, text)?
            {
                return Err(unavailable(format!(
                    "registry epoch {name} differs from this interpreter's supported consolidation semantics"
                )));
            }
            if name == "reason_codes" {
                let fields = ["code", "scope", "name", "meaning"];
                if archived.root.len() != 1
                    || !archived.tables.is_empty()
                    || archived.arrays.keys().any(|name| name != "reason")
                    || archived.arrays.get("reason").is_some_and(|rows| {
                        rows.len() > 4096
                            || rows.iter().any(|row| {
                                row.len() != fields.len()
                                    || row.keys().any(|key| !fields.contains(&key.as_str()))
                            })
                    })
                {
                    return Err(unavailable(
                        "registry epoch reasons contain fields outside the supported reason schema",
                    ));
                }
                // The archived labels describe committed preparer reasons.
                // They do not select an arithmetic law or posting authority.
                // Validate their schema and retain their original meanings;
                // never replace them with labels from the current executable.
                fa_registry::reason_codes::ReasonCodes::from_text(text)
                    .map_err(|error| unavailable(format!("unsupported epoch reasons: {error}")))?;
            }
        }
        // Parse the pinned source as source metadata. It does not choose or
        // load a historical binary. Native Database::replay remains mandatory.
        fa_registry::FoundationStack::parse(&self.sources[3].1).map_err(|error| {
            unavailable(format!("invalid epoch foundation provenance: {error}"))
        })?;
        if !self.units_match(units, false)? {
            return Err(unavailable(
                "registry epoch unit meanings differ from the book's immutable unit table",
            ));
        }
        Ok(())
    }

    fn units_match(&self, units: &fa_money::UnitRegistry, exact: bool) -> Result<bool, Refusal> {
        let doc = document("units", &self.sources[2].1)?;
        let fields = [
            "id",
            "code",
            "version",
            "scale",
            "kind",
            "iso4217",
            "rounding_default",
            "balance_policy",
        ];
        if doc.root.len() != 1
            || !doc.tables.is_empty()
            || doc.arrays.keys().any(|name| name != "unit")
            || doc.arrays.get("unit").is_some_and(|rows| {
                rows.iter().any(|row| {
                    row.keys().any(|key| !fields.contains(&key.as_str()))
                        || (row.contains_key("iso4217")
                            && row.get("kind").and_then(Value::as_str) != Some("currency"))
                })
            })
        {
            return Err(unavailable(
                "registry epoch units contain fields outside this interpreter's supported unit schema",
            ));
        }
        let rows = fa_registry::parse_units(&self.sources[2].1)
            .map_err(|error| unavailable(format!("unsupported registry epoch units: {error}")))?;
        if exact && rows.len() != units.len() {
            return Ok(false);
        }
        for (id, unit) in units.iter() {
            let Some(row) = rows.get(id.0 as usize) else {
                return Ok(false);
            };
            let (kind, iso4217) = match unit.kind {
                fa_money::UnitKind::Currency { iso4217 } => ("currency", Some(iso4217)),
                fa_money::UnitKind::Commodity => ("commodity", None),
                fa_money::UnitKind::Share => ("share", None),
                fa_money::UnitKind::Time => ("time", None),
                fa_money::UnitKind::Count => ("count", None),
                fa_money::UnitKind::Custom => ("custom", None),
            };
            let balance = if unit.allows_single_sided() {
                "single_sided"
            } else {
                "balanced"
            };
            if row.id != id.0
                || row.code != unit.code
                || row.version != unit.version
                || row.scale != unit.scale
                || row.kind != kind
                || row.iso4217 != iso4217
                || fa_money::RoundingLaw::from_id(row.rounding_default)
                    != Some(unit.rounding_default)
                || row.balance_policy != balance
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub(crate) fn check_explanation_reasons(
        &self,
        explanation: &BalanceExplanation,
    ) -> Result<(), Refusal> {
        let Some((name, source)) = self.sources.get(4) else {
            return Err(unavailable("the explanation epoch omits reason_codes"));
        };
        if name != "reason_codes" {
            return Err(unavailable(
                "the explanation epoch has another fifth source",
            ));
        }
        let reasons = fa_registry::reason_codes::ReasonCodes::from_text(source)
            .map_err(|error| unavailable(format!("unsupported epoch reasons: {error}")))?;
        for contribution in &explanation.contributions {
            for link in &contribution.supersedes {
                if reasons.get("supersession", link.reason_code).is_none() {
                    return Err(Refusal::new(
                        fa_notary::code::SCOPE_UNSUPPORTED,
                        exit::REFUSAL,
                        format!(
                            "explanation entry {:032x} cites supersession reason {} absent from its archived reason-code registry",
                            contribution.entry.0, link.reason_code,
                        ),
                        "plan §8.2 / §13.6 (a portable explanation preserves the registered meaning of each displayed reason)",
                        "replay this historical explanation in its source book; preserve the original certificate and reason sources until an independent interpreter supports its reason representation",
                    ));
                }
            }
        }
        Ok(())
    }

    pub(crate) fn offline_documents(
        &self,
        units: &fa_money::UnitRegistry,
    ) -> Result<Vec<(String, Vec<u8>)>, Refusal> {
        self.admit(units)?;
        if !self.units_match(units, true)? {
            return Err(Refusal::new(
                fa_notary::code::SCOPE_UNSUPPORTED,
                exit::REFUSAL,
                "the archived registry does not enumerate exactly the report's book units",
                "plan §13.6 / FA-INV-11 (the offline unit universe must be exact)",
                "use a report whose retained unit epoch matches its complete book unit table",
            ));
        }
        self.sources
            .iter()
            .map(|(name, text)| Ok((name.clone(), document(name, text)?.canonical_bytes())))
            .collect()
    }
}

fn vid(book_id: Id128, closure: &[u8; 32]) -> VId {
    let hash = domain_digest(b"fa:vid:report-registry-epoch:v1", &[&book_id.0, closure]);
    VId(u128::from_le_bytes(
        hash[..16].try_into().expect("16-byte identity"),
    ))
}

fn read_row<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    closure: &[u8; 32],
    row: &VertexRow,
    at: CommitSeq,
) -> Outcome<Epoch> {
    cx.checkpoint().map_err(BookError::Context)?;
    let Some(before) = row.created_at.0.checked_sub(1) else {
        return Ok(Err(invalid(
            "registry epoch has no original creating commit",
        )));
    };
    if row.vid != vid(book.book_id, closure)
        || row.labels.as_slice() != [STORAGE_LABEL]
        || row.retired_at.is_some()
        || row.props.len() != 3
        || !matches!(prop(row, property::BOOK_ID), Some(CanonicalScalar::Bytes(bytes)) if bytes.as_slice() == book.book_id.0)
        || db
            .vertex_at(row.vid, CommitSeq(before))
            .map_err(fa_journal::KernelError::from)?
            .is_some()
        || db
            .vertex_at(row.vid, row.created_at)
            .map_err(fa_journal::KernelError::from)?
            .as_ref()
            != Some(row)
    {
        return Ok(Err(invalid(
            "registry epoch identity, book binding or immutable creating record differs",
        )));
    }
    let bytes = match object::read(
        db,
        cx,
        book.book_id,
        row,
        STORAGE_LABEL,
        ObjectKind::RegistryEpoch,
        at,
        MAX_EPOCH_BYTES,
    ) {
        Ok(bytes) => bytes,
        Err(fa_journal::KernelError::Corrupt(why)) => return Ok(Err(invalid(why))),
        Err(error) => return Err(error.into()),
    };
    if !matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == digest(FORMAT, &bytes))
    {
        return Ok(Err(invalid(
            "registry epoch's exact source bytes were changed",
        )));
    }
    let epoch = match Epoch::decode(&bytes) {
        Ok(epoch) => epoch,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if epoch.book_id != book.book_id || epoch.closure != *closure {
        return Ok(Err(invalid(
            "registry epoch belongs to another book or closure",
        )));
    }
    Ok(Ok(epoch))
}

/// Resolve only source transcripts originally retained in this book. A supplied
/// certificate cannot inject source text or make it an executable policy.
pub(crate) fn resolve<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
) -> Outcome<Option<Epoch>> {
    if !supports(&certificate.selection) {
        return Ok(Ok(None));
    }
    cx.checkpoint().map_err(BookError::Context)?;
    let at = db.frontier().map_err(fa_journal::KernelError::from)?;
    let Some(row) = db
        .vertex_at(vid(book.book_id, &certificate.registry_digest), at)
        .map_err(fa_journal::KernelError::from)?
    else {
        return Ok(Ok(None));
    };
    let epoch = match read_row(db, cx, book, &certificate.registry_digest, &row, at)? {
        Ok(epoch) => epoch,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if let Err(refusal) = epoch.admit_for(&certificate.selection, &book.units) {
        return Ok(Err(refusal));
    }
    Ok(Ok(Some(epoch)))
}

/// Append to the caller's certificate-retention transaction. The root absence
/// is witnessed; all fragments and the certificate are indivisible. This path
/// receives authority only from the existing retention admission, and never
/// activates or changes a book policy.
pub(crate) fn stage<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    certificate: &ReportCertificate,
    txn: &mut WriteTxn,
    batch: &mut WriteBatch,
) -> Outcome<()> {
    if !supports(&certificate.selection) {
        return Ok(Ok(()));
    }
    let root = vid(book.book_id, &certificate.registry_digest);
    if let Some(row) = txn
        .vertex(db, root)
        .map_err(fa_journal::KernelError::from)?
    {
        return Ok(read_row(
            db,
            cx,
            book,
            &certificate.registry_digest,
            &row,
            txn.basis(),
        )?
        .and_then(|epoch| epoch.admit_for(&certificate.selection, &book.units)));
    }
    let epoch = match Epoch::for_selection(book.book_id, &certificate.selection) {
        Ok(epoch) => epoch,
        Err(refusal) => return Ok(Err(refusal)),
    };
    // Historical legacy closures keep their original contract. We cannot
    // reconstruct a source epoch this binary never held. Custom unit tables
    // likewise retain the old native-context replay without a false epoch.
    let matching_units = match epoch.units_match(&book.units, false) {
        Ok(matches) => matches,
        Err(refusal) => return Ok(Err(refusal)),
    };
    if epoch.closure != certificate.registry_digest || !matching_units {
        return Ok(Ok(()));
    }
    let bytes = match epoch.encode() {
        Ok(bytes) => bytes,
        Err(refusal) => return Ok(Err(refusal)),
    };
    object::stage(
        cx,
        batch,
        book.book_id,
        root,
        STORAGE_LABEL,
        ObjectKind::RegistryEpoch,
        &bytes,
    )?;
    batch.create_vertex(
        root,
        vec![STORAGE_LABEL],
        vec![
            (
                property::FA_PAYLOAD,
                scalar_bytes(
                    "registry epoch",
                    object::payload(ObjectKind::RegistryEpoch, &bytes)?,
                )?,
            ),
            (
                property::FA_DIGEST,
                scalar_bytes(
                    "registry epoch source digest",
                    digest(FORMAT, &bytes).to_vec(),
                )?,
            ),
            (
                property::BOOK_ID,
                scalar_bytes("registry epoch book", book.book_id.0.to_vec())?,
            ),
        ],
    );
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate_store::tests::Harness;
    use fa_model::symbols::relation;

    fn certificate(h: &Harness, statement: bool) -> ReportCertificate {
        let selection = if statement {
            ReportSelection::from(crate::StatementSelection {
                definition: crate::StatementDefinition::embedded("balance-sheet").unwrap(),
                periods: vec!["FY2026-P01".into()],
                comparative: Vec::new(),
            })
        } else {
            ReportSelection::TrialBalance(TrialBalanceSelection::Periods(vec!["FY2026-P01".into()]))
        };
        h.book
            .certify_report(&h.cx(), selection, None)
            .unwrap()
            .unwrap()
            .certificate
    }

    fn open_items_certificate(h: &Harness, account: Option<VId>) -> ReportCertificate {
        h.book
            .certify_report(&h.cx(), ReportSelection::OpenItems { account }, None)
            .unwrap()
            .unwrap()
            .certificate
    }

    /// A retained source transcript from a different executable build. The
    /// fixture changes build provenance only, never native evidence or amounts.
    /// Unlike an API that bypasses admission, it uses an actual native commit
    /// and the same immutable object format a prior producer would have written.
    fn publish_epoch(h: &mut Harness, epoch: &Epoch) {
        let bytes = epoch.encode().unwrap();
        let root = vid(epoch.book_id, &epoch.closure);
        let mut batch = WriteBatch::new(relation::DERIVED_FROM);
        object::stage(
            &h.cx().query(),
            &mut batch,
            epoch.book_id,
            root,
            STORAGE_LABEL,
            ObjectKind::RegistryEpoch,
            &bytes,
        )
        .unwrap();
        batch.create_vertex(
            root,
            vec![STORAGE_LABEL],
            vec![
                (
                    property::FA_PAYLOAD,
                    scalar_bytes(
                        "epoch",
                        object::payload(ObjectKind::RegistryEpoch, &bytes).unwrap(),
                    )
                    .unwrap(),
                ),
                (
                    property::FA_DIGEST,
                    scalar_bytes("digest", digest(FORMAT, &bytes).to_vec()).unwrap(),
                ),
                (
                    property::BOOK_ID,
                    scalar_bytes("book", epoch.book_id.0.to_vec()).unwrap(),
                ),
            ],
        );
        h.write(batch);
    }

    fn historical_epoch(book: Id128) -> Epoch {
        let mut sources = Epoch::current(book).unwrap().sources;
        sources[3].1 = sources[3]
            .1
            .replace("taken_on = \"2026-10-10\"", "taken_on = \"2026-09-01\"")
            // A syntactically valid synthetic prior pin exercises the source
            // revision boundary. This fixture does not execute that binary:
            // every native input is still replayed by the actual linked DB.
            .replace(
                "b323bd17ceaf81e97ce89e43d8d9f6d5151695cf",
                "a323bd17ceaf81e97ce89e43d8d9f6d5151695cf",
            );
        assert!(
            sources[3]
                .1
                .contains("a323bd17ceaf81e97ce89e43d8d9f6d5151695cf")
        );
        Epoch::new(book, sources).unwrap()
    }

    #[test]
    fn registry_epoch_round_trip_preserves_exact_sources_and_refuses_changed_meanings() {
        let book = Id128([7; 16]);
        let epoch = Epoch::current(book).unwrap();
        let encoded = epoch.encode().unwrap();
        assert!(
            encoded.len() > object::CHUNK_BYTES,
            "real registry closure needs fragments"
        );
        assert_eq!(Epoch::decode(&encoded).unwrap(), epoch);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        epoch.admit(&units).unwrap();
        let old = historical_epoch(book);
        assert_ne!(old.closure, epoch.closure);
        old.admit(&units).unwrap();
        let mut unsupported = encoded.clone();
        unsupported[FORMAT.len() - 1] = b'2';
        assert_eq!(
            Epoch::decode(&unsupported).unwrap_err().code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE
        );
        let mut tampered = encoded.clone();
        tampered[FORMAT.len() + 16] ^= 1;
        assert!(Epoch::decode(&tampered).is_err());
        let mut trailing = encoded;
        trailing.push(0);
        assert!(Epoch::decode(&trailing).is_err());

        for (index, from, to) in [
            (0, "normal_balance = 0", "normal_balance = 1"),
            (1, "supersession = \"reverses\"", "supersession = \"none\""),
            (1, "carries_open_items = true", "carries_open_items = false"),
            (2, "scale = 2", "scale = 3"),
            (
                2,
                "rounding_default = 3",
                "rounding_default = 3\nunknown_unit_semantics = 1",
            ),
            (3, "schema_version = 1", "schema_version = 2"),
        ] {
            let mut sources = epoch.sources.clone();
            assert!(
                sources[index].1.contains(from),
                "negative must change an actual field"
            );
            sources[index].1 = sources[index].1.replacen(from, to, 1);
            let changed = Epoch::new(book, sources).unwrap();
            assert_ne!(changed.closure, epoch.closure);
            assert_eq!(
                changed.admit(&units).unwrap_err().code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE
            );
        }
    }

    #[test]
    fn consolidation_epochs_preserve_exact_roles_and_laws_without_borrowing_other_profiles() {
        let book = Id128([0xc6; 16]);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let native = ReportSelection::Consolidation {
            period: "FY2026-P01".into(),
        };
        let functional = ReportSelection::FunctionalConsolidation {
            period: "FY2026-P01".into(),
        };
        for selection in [&native, &functional] {
            let epoch = Epoch::for_selection(book, selection).unwrap();
            assert!(supports(selection));
            assert_eq!(epoch.closure, registry_digest(selection).unwrap());
            assert_eq!(Epoch::decode(&epoch.encode().unwrap()).unwrap(), epoch);
            epoch.admit_for(selection, &units).unwrap();
            let docs = epoch.offline_documents(&units).unwrap();
            assert_eq!(
                docs.len(),
                if selection.uses_functional_valuations() {
                    7
                } else {
                    6
                }
            );
            for (name, from, to) in [
                (
                    "account_roles",
                    "name = \"intercompany\"",
                    "name = \"intercompany_changed\"",
                ),
                (
                    "rounding_laws",
                    "name = \"HalfEven\"",
                    "name = \"HalfEvenChanged\"",
                ),
                (
                    "fx_laws",
                    "rounding_law = \"HalfEven\"",
                    "rounding_law = \"HalfUp\"",
                ),
            ] {
                let mut sources = epoch.sources.clone();
                let Some((_, source)) = sources
                    .iter_mut()
                    .find(|(source_name, _)| source_name == name)
                else {
                    continue;
                };
                assert!(
                    source.contains(from),
                    "negative changes a real {name} meaning"
                );
                *source = source.replacen(from, to, 1);
                let changed = Epoch::new(book, sources).unwrap();
                assert_ne!(changed.closure, epoch.closure);
                assert_eq!(
                    changed.admit_for(selection, &units).unwrap_err().code,
                    code::CERTIFICATE_REGISTRY_UNAVAILABLE
                );
            }
            for other in [
                &ReportSelection::TrialBalance(TrialBalanceSelection::Periods(vec![
                    "FY2026-P01".into(),
                ])),
                if selection.uses_functional_valuations() {
                    &native
                } else {
                    &functional
                },
            ] {
                assert_eq!(
                    epoch.admit_for(other, &units).unwrap_err().code,
                    code::CERTIFICATE_REGISTRY_UNAVAILABLE
                );
            }
        }
    }

    #[test]
    fn registry_epoch_is_atomic_with_first_retention_shared_by_reports_and_reopened() {
        let (mut h, _) = Harness::with_posts(1);
        let tb = certificate(&h, false);
        let statement = certificate(&h, true);
        let open_items = open_items_certificate(&h, None);
        let before = h.head();
        let ack = h.retain(&open_items).unwrap();
        assert_eq!(ack.recorded_at.0, before.0 + 1);
        let book = h.book.context();
        let root = vid(book.book_id, &tb.registry_digest);
        assert!(h.book.db.vertex_at(root, before).unwrap().is_none());
        let archived = resolve(&h.book.db, &h.cx().query(), book, &tb)
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(archived, Epoch::current(book.book_id).unwrap());
        let fragment_digest = domain_digest(
            b"fa:object-content:v1",
            &[
                &(ObjectKind::RegistryEpoch as u16).to_le_bytes(),
                &archived.encode().unwrap(),
            ],
        );
        let is_epoch_record = |row: &VertexRow| {
            row.labels.as_slice() == [STORAGE_LABEL]
                && (row.vid == root
                    || matches!(prop(row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == fragment_digest))
        };
        let rows = h.book.db.vertices_at(ack.recorded_at).unwrap();
        let epoch_rows = rows
            .iter()
            .filter(|row| is_epoch_record(row))
            .collect::<Vec<_>>();
        assert!(epoch_rows.len() > 1);
        assert!(
            epoch_rows
                .iter()
                .all(|row| row.created_at == ack.recorded_at)
        );
        assert_eq!(h.retain(&open_items).unwrap(), ack);
        assert_eq!(
            h.head(),
            ack.recorded_at,
            "an exact retry publishes nothing"
        );
        h.retain(&tb).unwrap();
        h.retain(&statement).unwrap();
        let rows = h.book.db.vertices_at(h.head()).unwrap();
        assert_eq!(
            rows.iter().filter(|row| is_epoch_record(row)).count(),
            epoch_rows.len(),
            "one shared epoch, no copy per certificate"
        );
        let h = h.reopen();
        for expected in [tb, open_items, statement] {
            let saved = h.read(&expected.digest).unwrap();
            assert_eq!(
                saved.canonical_bytes().unwrap(),
                expected.canonical_bytes().unwrap()
            );
            let replay = h.book.replay_report(&h.cx(), &saved).unwrap().unwrap();
            assert_eq!(replay.canonical_bytes().unwrap(), expected.output);
        }
    }

    #[test]
    fn registry_epoch_open_items_replays_archived_sources_after_reopen() {
        for filtered in [false, true] {
            let (mut h, _) = Harness::with_posts(1);
            let account = filtered.then(|| fa_model::account_vid(h.book.context().book_id, "1000"));
            let original = open_items_certificate(&h, account);
            let epoch = historical_epoch(h.book.context().book_id);
            let historical = original.resealed_under(epoch.closure);
            assert_ne!(historical.registry_digest, original.registry_digest);
            assert_eq!(
                h.book
                    .replay_report(&h.cx(), &historical)
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE,
                "an unretained historical source closure is unavailable"
            );
            publish_epoch(&mut h, &epoch);
            let ack = h.retain(&historical).unwrap();
            let mut h = h.reopen();
            let stored = h.read(&historical.digest).unwrap();
            let before = h.head();
            let replay = h.book.replay_report(&h.cx(), &stored).unwrap().unwrap();
            assert_eq!(replay.canonical_bytes().unwrap(), original.output);
            let ReportOutput::OpenItems(report) = replay else {
                panic!("the archived selector must remain an open-item report");
            };
            assert_eq!(report.account_filter, account);
            assert_eq!(report.items.len(), if filtered { 1 } else { 2 });
            assert!(report.items.iter().all(|item| item.open == 100));
            assert_eq!(report.accounts.len(), if filtered { 1 } else { 2 });
            let archived = resolve(&h.book.db, &h.cx().query(), h.book.context(), &stored)
                .unwrap()
                .unwrap()
                .unwrap();
            let docs = archived.offline_documents(&h.book.context().units).unwrap();
            assert_eq!(
                docs[3].1,
                document("foundations", &epoch.sources[3].1)
                    .unwrap()
                    .canonical_bytes()
            );
            assert_ne!(
                docs[3].1,
                document("foundations", REPORT_REGISTRIES[3].1)
                    .unwrap()
                    .canonical_bytes()
            );
            assert_eq!(h.retain(&stored).unwrap(), ack);
            assert_eq!(h.head(), before, "replay, export and retry publish nothing");

            let mut wrong_native = stored.clone();
            wrong_native.inputs[0].result_digest.0[0] ^= 1;
            wrong_native = wrong_native.resealed_under(epoch.closure);
            let refusal = h
                .book
                .replay_report(&h.cx(), &wrong_native)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, code::CERTIFICATE_INVALID);
            assert!(refusal.message.contains("native input"));
            let mut wrong_output = stored;
            wrong_output.output[0] ^= 1;
            wrong_output.output_digest = digest(b"fa:report-output:v1", &wrong_output.output);
            wrong_output = wrong_output.resealed_under(epoch.closure);
            assert_eq!(
                h.book
                    .replay_report(&h.cx(), &wrong_output)
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::CERTIFICATE_INVALID
            );
        }
    }

    #[test]
    fn registry_epoch_open_items_rejects_resealed_application_and_lineage_meanings() {
        for (from, to) in [
            ("carries_open_items = true", "carries_open_items = false"),
            ("supersession = \"reverses\"", "supersession = \"none\""),
        ] {
            let (mut h, _) = Harness::with_posts(1);
            let original = open_items_certificate(&h, None);
            let mut sources = Epoch::current(h.book.context().book_id).unwrap().sources;
            assert!(sources[1].1.contains(from));
            sources[1].1 = sources[1].1.replacen(from, to, 1);
            let incompatible = Epoch::new(h.book.context().book_id, sources).unwrap();
            assert_ne!(incompatible.closure, original.registry_digest);
            publish_epoch(&mut h, &incompatible);
            let changed = original.resealed_under(incompatible.closure);
            let before = h.head();
            assert_eq!(
                h.book
                    .replay_report(&h.cx(), &changed)
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE
            );
            assert_eq!(
                h.retain(&changed).unwrap_err().code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE
            );
            assert_eq!(
                h.head(),
                before,
                "incompatible source admission writes nothing"
            );
        }
    }

    #[test]
    fn registry_epoch_replays_archived_foundations_and_still_checks_every_native_input() {
        let (mut h, _) = Harness::with_posts(1);
        for statement in [false, true] {
            let original = certificate(&h, statement);
            let epoch = historical_epoch(h.book.context().book_id);
            let historical = original.resealed_under(epoch.closure);
            assert_ne!(historical.registry_digest, original.registry_digest);
            if !statement {
                assert_eq!(
                    h.book
                        .replay_report(&h.cx(), &historical)
                        .unwrap()
                        .unwrap_err()
                        .code,
                    code::CERTIFICATE_REGISTRY_UNAVAILABLE
                );
                publish_epoch(&mut h, &epoch);
            }
            h.retain(&historical).unwrap();
            let stored = h.read(&historical.digest).unwrap();
            let replay = h.book.replay_report(&h.cx(), &stored).unwrap().unwrap();
            assert_eq!(replay.canonical_bytes().unwrap(), original.output);
            if statement {
                let docs = offline_report_registries_at(
                    &h.book.db,
                    &h.cx().query(),
                    h.book.context(),
                    &stored,
                )
                .unwrap()
                .unwrap();
                assert_eq!(
                    docs[3].1,
                    document("foundations", &epoch.sources[3].1)
                        .unwrap()
                        .canonical_bytes()
                );
                assert_ne!(
                    docs[3].1,
                    document("foundations", REPORT_REGISTRIES[3].1)
                        .unwrap()
                        .canonical_bytes()
                );
                let cx = h.cx();
                let principal = VId(1);
                let authority =
                    fa_journal::Capability::embedded(principal, &["read", "produce", "witness"])
                        .unwrap();
                let checkpoint = h
                    .runtime
                    .block_on(h.book.checkpoint(&cx, principal, &authority))
                    .unwrap()
                    .unwrap();
                let state = checkpoint.checkpoint.checkpoint.body.state_oid;
                let before_export = h.head();
                let produced = h
                    .runtime
                    .block_on(h.book.produce_report_bundle(
                        &cx,
                        principal,
                        &authority,
                        Some(state),
                        &stored,
                    ))
                    .unwrap()
                    .unwrap()
                    .unwrap();
                assert_eq!(h.head(), before_export, "export never writes an epoch");
                let key = h.book.checkpoint_public_key();
                let anchor =
                    fa_verify::verify_checkpoint(&produced.checkpoint.bytes, &[key]).unwrap();
                let units = h
                    .book
                    .context()
                    .units
                    .iter()
                    .map(|(id, _)| id.0)
                    .collect::<Vec<_>>();
                let verified = fa_verify::report::verify_statement_report_expected(
                    &produced.bundle.bytes,
                    &[key],
                    Some(&anchor.checkpoint),
                    Some(&produced.receipt),
                    &units,
                    Some(&stored.digest),
                )
                .expect("outsider verification uses the archived foundation closure");
                assert_eq!(verified.output, original.output);
                assert_eq!(verified.certificate_digest, stored.digest);
                assert_eq!(verified.known_at, stored.known_at.0);
                assert_eq!(verified.unit_universe_source, "authenticated-registry");
            }
            let mut wrong_native = stored.clone();
            wrong_native.inputs[0].result_digest.0[0] ^= 1;
            wrong_native = wrong_native.resealed_under(epoch.closure);
            let refusal = h
                .book
                .replay_report(&h.cx(), &wrong_native)
                .unwrap()
                .unwrap_err();
            assert_eq!(refusal.code, code::CERTIFICATE_INVALID);
            assert!(
                refusal.message.contains("native input"),
                "{}",
                refusal.message
            );
            let mut wrong_output = stored;
            wrong_output.output[0] ^= 1;
            wrong_output.output_digest = digest(b"fa:report-output:v1", &wrong_output.output);
            wrong_output = wrong_output.resealed_under(epoch.closure);
            assert_eq!(
                h.book
                    .replay_report(&h.cx(), &wrong_output)
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::CERTIFICATE_INVALID
            );
        }
    }

    #[test]
    fn registry_epoch_resealed_incompatible_sources_and_restored_storage_are_refused() {
        let (mut h, _) = Harness::with_posts(1);
        let original = certificate(&h, false);
        let mut sources = Epoch::current(h.book.context().book_id).unwrap().sources;
        sources[1].1 = sources[1]
            .1
            .replace("supersession = \"reverses\"", "supersession = \"none\"");
        let incompatible = Epoch::new(h.book.context().book_id, sources).unwrap();
        publish_epoch(&mut h, &incompatible);
        let changed = original.resealed_under(incompatible.closure);
        let before = h.head();
        assert_eq!(
            h.book
                .replay_report(&h.cx(), &changed)
                .unwrap()
                .unwrap_err()
                .code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE
        );
        assert_eq!(
            h.retain(&changed).unwrap_err().code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE
        );
        assert_eq!(h.head(), before, "failed semantic admission writes nothing");

        h.retain(&original).unwrap();
        let root = vid(h.book.context().book_id, &original.registry_digest);
        let row = h.book.db.vertex(root).unwrap().unwrap();
        let original_payload = prop(&row, property::FA_PAYLOAD).unwrap().clone();
        let mut damage = WriteBatch::new(relation::DERIVED_FROM);
        damage.set_vertex_property(
            root,
            property::FA_PAYLOAD,
            Some(scalar_bytes("damage", b"corrupt".to_vec()).unwrap()),
        );
        h.write(damage);
        let mut restore = WriteBatch::new(relation::DERIVED_FROM);
        restore.set_vertex_property(root, property::FA_PAYLOAD, Some(original_payload));
        h.write(restore);
        let before = h.head();
        assert_eq!(
            h.book
                .replay_report(&h.cx(), &original)
                .unwrap()
                .unwrap_err()
                .code,
            code::CERTIFICATE_INVALID
        );
        assert_eq!(h.head(), before, "replay never repairs registry history");
    }

    fn explanation_certificate(h: &Harness) -> ReportCertificate {
        h.book
            .certify_report(
                &h.cx(),
                ReportSelection::ExplainBalance {
                    account: fa_model::account_vid(h.book.context().book_id, "1000"),
                    period: "FY2026-P01".into(),
                },
                None,
            )
            .unwrap()
            .unwrap()
            .certificate
    }

    #[test]
    fn explanation_epochs_preserve_four_source_bytes_and_require_exact_five_source_profiles() {
        let book = Id128([0x67; 16]);
        let units = fa_money::UnitRegistry::embedded().unwrap();
        let selection = ReportSelection::ExplainBalance {
            account: VId(1),
            period: "FY2026-P01".into(),
        };
        let old = Epoch::current(book).unwrap();
        let old_bytes = old.encode().unwrap();
        assert_eq!(old.sources.len(), 4);
        assert_eq!(
            Epoch::decode(&old_bytes).unwrap().encode().unwrap(),
            old_bytes
        );
        let explanation = Epoch::for_selection(book, &selection).unwrap();
        assert_eq!(
            explanation
                .sources
                .iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            EXPLANATION_NAMES,
        );
        assert_eq!(&explanation.sources[..4], old.sources.as_slice());
        assert_ne!(explanation.closure, old.closure);
        explanation.admit_for(&selection, &units).unwrap();
        assert_eq!(
            Epoch::decode(&explanation.encode().unwrap()).unwrap(),
            explanation
        );
        assert_eq!(
            old.admit_for(&selection, &units).unwrap_err().code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE,
        );
        assert_eq!(
            explanation
                .admit_for(
                    &ReportSelection::TrialBalance(TrialBalanceSelection::Periods(vec![
                        "FY2026-P01".into()
                    ])),
                    &units,
                )
                .unwrap_err()
                .code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE,
        );
        let mut reordered = explanation.sources.clone();
        reordered.swap(3, 4);
        assert!(Epoch::new(book, reordered).is_err());
        for (from, to) in [
            ("code = 1", "code = 0"),
            ("scope = \"supersession\"", "scope = \"unregistered\""),
            (
                "name = \"DataEntryError\"",
                "name = \"DataEntryError\"\nunknown_reason_law = 1",
            ),
        ] {
            let mut sources = explanation.sources.clone();
            assert!(sources[4].1.contains(from));
            sources[4].1 = sources[4].1.replacen(from, to, 1);
            let changed = Epoch::new(book, sources).unwrap();
            assert_eq!(
                changed.admit_for(&selection, &units).unwrap_err().code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE,
            );
        }
    }

    #[test]
    fn retained_explanations_export_original_reason_sources_after_reopen() {
        let (mut h, _) = Harness::with_posts(1);
        let original = explanation_certificate(&h);
        let before = h.head();
        assert_eq!(
            offline_report_registries_at(&h.book.db, &h.cx().query(), h.book.context(), &original)
                .unwrap()
                .unwrap_err()
                .code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE,
            "a current executable cannot replace an unarchived original reason transcript",
        );
        assert_eq!(h.head(), before);

        let mut sources = historical_epoch(h.book.context().book_id).sources;
        sources.push((
            REASON_CODES.0.into(),
            REASON_CODES
                .1
                .replace(
                    "name = \"DataEntryError\"",
                    "name = \"HistoricalDataEntryError\"",
                )
                .replace(
                    "the preparer states that the original fact was entered incorrectly",
                    "the original producer recorded this historical correction meaning",
                ),
        ));
        let epoch = Epoch::new(h.book.context().book_id, sources).unwrap();
        let historical = original.resealed_under(epoch.closure);
        publish_epoch(&mut h, &epoch);
        let ack = h.retain(&historical).unwrap();
        let mut h = h.reopen();
        let stored = h.read(&historical.digest).unwrap();
        let before = h.head();
        let report = h.book.replay_report(&h.cx(), &stored).unwrap().unwrap();
        assert_eq!(report.canonical_bytes().unwrap(), original.output);
        let docs =
            offline_report_registries_at(&h.book.db, &h.cx().query(), h.book.context(), &stored)
                .unwrap()
                .unwrap();
        assert_eq!(docs.len(), 5);
        assert_eq!(docs[4].0, "reason_codes");
        assert_eq!(
            docs[4].1,
            document("reason_codes", &epoch.sources[4].1)
                .unwrap()
                .canonical_bytes()
        );
        assert_ne!(
            docs[4].1,
            document(REASON_CODES.0, REASON_CODES.1)
                .unwrap()
                .canonical_bytes()
        );
        assert_eq!(h.retain(&stored).unwrap(), ack);
        assert_eq!(
            h.head(),
            before,
            "replay, registry export and retention retry append nothing"
        );

        let cx = h.cx();
        let principal = VId(1);
        let authority =
            fa_journal::Capability::embedded(principal, &["read", "produce", "witness"]).unwrap();
        let checkpoint = h
            .runtime
            .block_on(h.book.checkpoint(&cx, principal, &authority))
            .unwrap()
            .unwrap();
        let state = checkpoint.checkpoint.checkpoint.body.state_oid;
        let before_export = h.head();
        let produced = h
            .runtime
            .block_on(h.book.produce_report_bundle(
                &cx,
                principal,
                &authority,
                Some(state),
                &stored,
            ))
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            h.head(),
            before_export,
            "portable export does not rewrite the archived epoch"
        );
        let key = h.book.checkpoint_public_key();
        let verified = fa_verify::report::verify_report_expected(
            &produced.bundle.bytes,
            &[key],
            None,
            Some(&produced.receipt),
            Some(&stored.digest),
        )
        .expect("outsider explanation replay uses the original reason source text");
        assert_eq!(verified.output, original.output);
        assert!(verified.explanation.is_some());
        assert_eq!(verified.unit_universe_source, "authenticated-registry");
    }

    #[test]
    fn resealed_explanations_cannot_borrow_another_report_registry_profile() {
        let (mut h, _) = Harness::with_posts(1);
        let tb = certificate(&h, false);
        let explanation = explanation_certificate(&h);
        h.retain(&tb).unwrap();
        h.retain(&explanation).unwrap();
        for changed in [
            explanation.resealed_under(tb.registry_digest),
            tb.resealed_under(explanation.registry_digest),
        ] {
            let before = h.head();
            assert_eq!(
                h.book
                    .replay_report(&h.cx(), &changed)
                    .unwrap()
                    .unwrap_err()
                    .code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE,
            );
            assert_eq!(
                h.retain(&changed).unwrap_err().code,
                code::CERTIFICATE_REGISTRY_UNAVAILABLE
            );
            assert_eq!(
                h.head(),
                before,
                "cross-profile admission cannot publish any source or certificate"
            );
        }
    }

    #[test]
    fn archived_reason_membership_is_checked_for_each_displayed_contribution() {
        let (h, _) = Harness::with_posts(1);
        let certificate = explanation_certificate(&h);
        let ReportOutput::ExplainBalance(mut report) = h
            .book
            .replay_report(&h.cx(), &certificate)
            .unwrap()
            .unwrap()
        else {
            panic!("explanation selector");
        };
        let epoch = Epoch::for_selection(h.book.context().book_id, &certificate.selection).unwrap();
        epoch.check_explanation_reasons(&report).unwrap();
        let contribution = report.contributions.first_mut().unwrap();
        contribution.supersedes = vec![fa_model::Supersession {
            target: fa_model::EntryRef {
                vid: contribution.entry,
                entry_digest: contribution.entry_digest,
            },
            kind: fa_model::SupersessionKind::Reverses,
            reason_code: 1,
        }];
        epoch.check_explanation_reasons(&report).unwrap();
        for reason in [0, u16::MAX] {
            report.contributions[0].supersedes[0].reason_code = reason;
            let refusal = epoch.check_explanation_reasons(&report).unwrap_err();
            assert_eq!(refusal.code, fa_notary::code::SCOPE_UNSUPPORTED);
            assert!(
                refusal
                    .message
                    .contains("absent from its archived reason-code registry")
            );
        }
    }

    #[test]
    fn explanation_reason_source_refuses_more_rows_than_the_independent_document_profile() {
        let book = Id128([0x68; 16]);
        let selection = ReportSelection::ExplainBalance {
            account: VId(1),
            period: "FY2026-P01".into(),
        };
        let mut sources = Epoch::for_selection(book, &selection).unwrap().sources;
        let initial = fa_registry::reason_codes::ReasonCodes::from_text(&sources[4].1)
            .unwrap()
            .rows
            .len();
        for index in initial..=4096 {
            sources[4].1.push_str(&format!(
                "\n[[reason]]\ncode = {}\nscope = \"supersession\"\nname = \"PortableReason{}\"\nmeaning = \"retained registered reason\"\n",
                index + 100, index,
            ));
        }
        assert!(sources[4].1.len() < MAX_SOURCE_BYTES);
        assert_eq!(
            fa_registry::reason_codes::ReasonCodes::from_text(&sources[4].1)
                .unwrap()
                .rows
                .len(),
            4097,
            "the source is valid for the native reason parser",
        );
        assert!(
            document("reason_codes", &sources[4].1)
                .unwrap()
                .canonical_bytes()
                .len()
                < MAX_SOURCE_BYTES
        );
        let epoch = Epoch::new(book, sources).unwrap();
        let units = fa_money::UnitRegistry::embedded().unwrap();
        assert_eq!(
            epoch.admit_for(&selection, &units).unwrap_err().code,
            code::CERTIFICATE_REGISTRY_UNAVAILABLE,
            "a producer must not issue a source document the independent decoder necessarily refuses",
        );
    }
}
