//! Fixed-frontier discovery of retained Finding runs. Native creation history,
//! not a live label scan, defines the inventory. Every returned summary is
//! recomputed from its full retained procedure certificate. Other manifests are
//! checked for native shape and occurrence coverage, not claimed replayed.

use std::collections::BTreeMap;

use super::*;

pub const MAX_FINDING_RUN_PAGE: usize = 32;
const CURSOR_FORMAT: &[u8] = b"fa:finding-run-cursor:v1";

/// A portable continuation selector, NOT a capability, MAC or completeness
/// proof. Its fixed frontier and inventory digest bind pagination across later
/// postings/reviews. A caller may choose an earlier valid anchor intentionally;
/// each request independently checks current authority and all native births.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRunCursor {
    book: Id128,
    known_at: CommitSeq,
    after: VId,
    inventory_digest: [u8; 32],
}

impl FindingRunCursor {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut w = Writer::new();
        w.fixed(CURSOR_FORMAT)
            .fixed(&self.book.0)
            .u64(self.known_at.0)
            .u128(self.after.0)
            .fixed(&self.inventory_digest);
        encoded(w)
    }

    /// Fixed-size decoding establishes framing only; the inventory entrypoint
    /// validates book, cutoff, digest and anchor against retained native data.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != CURSOR_FORMAT.len() + 16 + 8 + 16 + 32 {
            return Err(invalid("finding-run cursor has an invalid fixed length"));
        }
        let bytes = bytes
            .strip_prefix(CURSOR_FORMAT)
            .ok_or_else(|| invalid("unsupported finding-run cursor format"))?;
        let fail = |e| invalid(format!("finding-run cursor: {e}"));
        let mut r = Reader::new(bytes);
        let result = Self {
            book: Id128(r.fixed("cursor book").map_err(fail)?),
            known_at: CommitSeq(r.u64("cursor frontier").map_err(fail)?),
            after: VId(r.u128("cursor anchor").map_err(fail)?),
            inventory_digest: r.fixed("cursor inventory").map_err(fail)?,
        };
        r.finish().map_err(fail)?;
        Ok(result)
    }

    #[must_use]
    pub fn known_at(&self) -> CommitSeq {
        self.known_at
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRunPageRequest {
    /// First page's inclusive publication cutoff, defaulting to current HEAD.
    /// A continuation inherits its cutoff; supplying a different one refuses.
    pub known_at: Option<CommitSeq>,
    pub after: Option<FindingRunCursor>,
    pub limit: usize,
}

impl Default for FindingRunPageRequest {
    fn default() -> Self {
        Self {
            known_at: None,
            after: None,
            limit: 16,
        }
    }
}

/// Bounded metadata from the fully replayed original run. No current human
/// disposition is inferred; use finding_run_review_history for that question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRunSummary {
    pub run_vid: VId,
    pub certificate_digest: [u8; 32],
    pub recorded_at: CommitSeq,
    pub producer: VId,
    pub coordinate: Coordinate,
    pub procedure: String,
    pub version: u16,
    pub finding_count: u32,
    pub findings_digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindingRunPage {
    pub book_id: Id128,
    pub known_at: CommitSeq,
    /// All native Finding-family births were checked through current HEAD too;
    /// a pinned cursor cannot hide later retirement or rewriting of a run.
    pub checked_through: CommitSeq,
    pub inventory_digest: [u8; 32],
    /// Structurally checked complete run manifests at known_at. Only summaries
    /// in this page have also undergone full certificate/computation replay.
    pub total_recorded_runs: u32,
    /// Ascending (original publication, run VId), independent of graph scan order.
    pub runs: Vec<FindingRunSummary>,
    /// None means this fixed native inventory has no more runs after this page,
    /// not that all transactions have been analyzed or all findings reviewed.
    pub next_cursor: Option<FindingRunCursor>,
}

struct Manifest {
    id: VId,
    certificate: [u8; 32],
    born: CommitSeq,
    count: u32,
    findings_digest: [u8; 32],
    seen: BTreeSet<u32>,
}

fn manifest(payload: &[u8], book: Id128, id: VId, born: CommitSeq) -> Result<Manifest, Refusal> {
    if payload.len() != FINDING_RUN_FORMAT.len() + 16 + 32 + 4 + 32 {
        return Err(invalid("finding run manifest has an invalid fixed length"));
    }
    let bytes = payload
        .strip_prefix(FINDING_RUN_FORMAT)
        .ok_or_else(|| invalid("unsupported finding run manifest"))?;
    let fail = |e| invalid(format!("finding run manifest: {e}"));
    let mut r = Reader::new(bytes);
    let source_book = Id128(r.fixed("run book").map_err(fail)?);
    let certificate = r.fixed("run certificate").map_err(fail)?;
    let count = r.u32("run count").map_err(fail)?;
    let findings_digest = r.fixed("run findings digest").map_err(fail)?;
    r.finish().map_err(fail)?;
    if book != source_book
        || count as usize > MAX_RECORDED_FINDINGS
        || finding_run_vid(book, &certificate) != id
    {
        return Err(invalid(
            "finding run manifest has a different book, identity or unsupported size",
        ));
    }
    Ok(Manifest {
        id,
        certificate,
        born,
        count,
        findings_digest,
        seen: BTreeSet::new(),
    })
}

struct Catalog {
    through: CommitSeq,
    selected: CommitSeq,
    digest: [u8; 32],
    manifests: Vec<Manifest>,
}

/// Check the entire immutable original inventory, including empty runs and
/// every occurrence's same-birth membership. Orphans and unknown formats refuse
/// even when they would have fallen outside the requested result page.
fn catalog<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &PurposeContexts,
    book: &BookContext,
    at: CommitSeq,
) -> Outcome<Catalog> {
    let head = db.frontier().map_err(KernelError::from)?;
    if at > head {
        return Ok(Err(invalid(
            "finding inventory cutoff exceeds the native frontier",
        )));
    }
    let births = fa_journal::finding_history::finding_births(db, cx, head)?;
    let mut roots = BTreeMap::new();
    let mut occurrences = Vec::new();
    for (id, born) in births {
        cx.query().checkpoint().map_err(BookError::Context)?;
        let row = db
            .vertex_at(id, born)
            .map_err(KernelError::from)?
            .ok_or_else(|| {
                BookError::Kernel(KernelError::Corrupt("missing Finding birth row".into()))
            })?;
        let Some(CanonicalScalar::Bytes(payload)) = prop(&row, property::FA_PAYLOAD) else {
            return Ok(Err(invalid(
                "Finding inventory member lacks a canonical payload",
            )));
        };
        if row.props.len() != 3
            || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == book.book_id.0)
        {
            return Ok(Err(invalid(
                "Finding inventory member has invalid book or properties",
            )));
        }
        // Reviews are separate records, never another analytic run. Review
        // policy and evidence are deliberately not represented by this API.
        if payload
            .as_slice()
            .starts_with(review::FINDING_REVIEW_FORMAT)
        {
            continue;
        }
        if !matches!(prop(&row, property::FA_DIGEST), Some(CanonicalScalar::Bytes(b)) if b.as_slice() == domain_digest(b"fa:finding-record-digest:v1", &[payload.as_slice()]))
        {
            return Ok(Err(invalid(
                "Finding inventory member digest differs from its body",
            )));
        }
        if payload.as_slice().starts_with(FINDING_RUN_FORMAT) {
            let manifest = match manifest(payload.as_slice(), book.book_id, id, born) {
                Ok(m) => m,
                Err(r) => return Ok(Err(r)),
            };
            if roots.insert(manifest.certificate, manifest).is_some() {
                return Ok(Err(invalid(
                    "Finding inventory repeats a certificate publication",
                )));
            }
        } else if payload.as_slice().starts_with(FINDING_RECORD_FORMAT) {
            let (certificate, ordinal) = match locator(payload.as_slice(), book.book_id, id) {
                Ok(p) => p,
                Err(r) => return Ok(Err(r)),
            };
            occurrences.push((certificate, ordinal, born));
        } else {
            return Ok(Err(invalid(
                "unsupported Finding-family inventory format; refusing incomplete discovery",
            )));
        }
    }
    for (certificate, ordinal, born) in occurrences {
        let Some(run) = roots.get_mut(&certificate) else {
            return Ok(Err(invalid(
                "Finding inventory has an occurrence without its complete run",
            )));
        };
        if born != run.born || ordinal >= run.count || !run.seen.insert(ordinal) {
            return Ok(Err(invalid(
                "Finding inventory occurrence membership or publication differs",
            )));
        }
    }
    let mut manifests = Vec::new();
    for (_, run) in roots {
        if run.seen.len() != run.count as usize {
            return Ok(Err(invalid(
                "Finding inventory run has missing occurrences; no partial page",
            )));
        }
        if run.born <= at {
            manifests.push(run);
        }
    }
    manifests.sort_by_key(|run| (run.born, run.id));
    let mut identity = Writer::new();
    identity.fixed(&book.book_id.0).u64(at.0);
    for run in &manifests {
        identity
            .u128(run.id.0)
            .fixed(&run.certificate)
            .u64(run.born.0)
            .u32(run.count)
            .fixed(&run.findings_digest);
    }
    let bytes = match encoded(identity) {
        Ok(b) => b,
        Err(r) => return Ok(Err(r)),
    };
    let digest = domain_digest(b"fa:finding-inventory:v1", &[&bytes]);
    Ok(Ok(Catalog {
        through: head,
        selected: at,
        digest,
        manifests,
    }))
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Discover retained original runs without already knowing a certificate
    /// digest. Snapshot-bound pagination validates all native manifests and
    /// fully replays each returned run before emitting any page. An error in a
    /// page produces no partial successful response. No book mutation occurs.
    /// The inventory excludes certificates whose findings were never recorded.
    pub async fn finding_runs(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &FindingRunPageRequest,
    ) -> Outcome<FindingRunPage> {
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        if request.limit == 0 || request.limit > MAX_FINDING_RUN_PAGE {
            return Ok(Err(invalid(
                "finding inventory page size must be in 1..=32",
            )));
        }
        let head = self.head(cx)?;
        let at = if let Some(cursor) = &request.after {
            if cursor.book != self.context().book_id
                || request.known_at.is_some_and(|at| at != cursor.known_at)
            {
                return Ok(Err(invalid(
                    "finding inventory continuation has a different book or cutoff",
                )));
            }
            cursor.known_at
        } else {
            request.known_at.unwrap_or(head)
        };
        if let Err(r) = fa_journal::scratch::ensure_history(&mut self.db, cx).await? {
            return Ok(Err(r));
        }
        let catalog = match self.query(cx, |db, book| catalog(db, cx, book, at))? {
            Ok(c) => c,
            Err(r) => return Ok(Err(r)),
        };
        let start = if let Some(cursor) = &request.after {
            if cursor.inventory_digest != catalog.digest {
                return Ok(Err(invalid(
                    "finding inventory continuation does not match its complete native manifest",
                )));
            }
            match catalog.manifests.iter().position(|m| m.id == cursor.after) {
                Some(index) => index + 1,
                None => {
                    return Ok(Err(invalid(
                        "finding inventory continuation anchor is absent",
                    )));
                }
            }
        } else {
            0
        };
        let end = start
            .saturating_add(request.limit)
            .min(catalog.manifests.len());
        let mut runs = Vec::with_capacity(end - start);
        for manifest in &catalog.manifests[start..end] {
            cx.query().checkpoint().map_err(BookError::Context)?;
            let run = match self
                .read_findings(cx, principal, capability, &manifest.certificate)
                .await?
            {
                Ok(r) => r,
                Err(r) => return Ok(Err(r)),
            };
            if run.run_vid != manifest.id
                || run.recorded_at != manifest.born
                || run.finding_ids.len() != manifest.count as usize
                || run.report.findings_digest != manifest.findings_digest
            {
                return Ok(Err(invalid(
                    "discovered Finding manifest differs from native certificate replay",
                )));
            }
            runs.push(FindingRunSummary {
                run_vid: run.run_vid,
                certificate_digest: run.certificate_digest,
                recorded_at: run.recorded_at,
                producer: run.producer,
                coordinate: run.report.coordinate,
                procedure: run.report.procedure,
                version: run.report.version,
                finding_count: manifest.count,
                findings_digest: run.report.findings_digest,
            });
        }
        if self.head(cx)? != catalog.through {
            return Ok(Err(Refusal::new(
                fa_journal::refusal::code::CONFLICT,
                exit::CONFLICT,
                "book changed during finding inventory replay",
                "FA-INV-10/11",
                "retry the same fixed-frontier inventory request",
            )));
        }
        if let Err(r) = authorize(self, cx, principal, capability, false)? {
            return Ok(Err(r));
        }
        let next_cursor = if end < catalog.manifests.len() {
            Some(FindingRunCursor {
                book: self.context().book_id,
                known_at: catalog.selected,
                after: catalog.manifests[end - 1].id,
                inventory_digest: catalog.digest,
            })
        } else {
            None
        };
        Ok(Ok(FindingRunPage {
            book_id: self.context().book_id,
            known_at: catalog.selected,
            checked_through: catalog.through,
            inventory_digest: catalog.digest,
            total_recorded_runs: catalog.manifests.len() as u32,
            runs,
            next_cursor,
        }))
    }
}
