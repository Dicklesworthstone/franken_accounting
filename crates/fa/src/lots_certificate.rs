//! Certified native lot schedules over an authenticated open-item source.
//!
//! The certificate binds the selected account, recorded prefix, optional civil
//! cutoff, declared base unit, acquisition identities and every relief. Native
//! replay checks the historical book's actual base unit. An offline recipient
//! must supply its independently expected base unit: a certificate's own field
//! cannot authenticate the book's currency policy. This proves a schedule and
//! its provenance, not FIFO/LIFO selection, tax treatment or disposal admission.

use std::collections::BTreeMap;

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, UnitPolicy, exit};
use fa_model::symbols::label;
use fa_model::{AccountType, DecodeError, Entry, EntryClass, Id128, Reader, Writer, domain_digest};
use fa_money::{Amount, Side, UnitId, UnitKind};
use fa_policy::{Capability, Op};
use fa_time::DateDay;
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

use crate::{
    AsyncBook, BookError, LotsReport, Outcome, ReportCertificate, ReportOutput, ReportSelection,
};

pub const LOTS_CERTIFICATE_FORMAT: &[u8] = b"fa:lots-certificate:v1";
pub const LOTS_OUTPUT_FORMAT: &[u8] = b"fa:lots:v1";
const DIGEST_DOMAIN: &[u8] = b"fa:lots-certificate-digest:v1";
pub const MAX_LOTS_CERTIFICATE_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_LOTS_ROWS: usize = 1 << 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotsRequest {
    pub account: VId,
    pub effective_through: Option<DateDay>,
    /// None resolves HEAD once; replay expectations use an explicit sequence.
    pub known_at: Option<CommitSeq>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LotsCertificate {
    source: ReportCertificate,
    base_unit: UnitId,
    effective_through: Option<DateDay>,
    producer: VId,
    capability_commitment: [u8; 32],
    output: Vec<u8>,
    digest: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertifiedLots {
    pub report: LotsReport,
    pub certificate: LotsCertificate,
}

fn invalid(message: impl Into<String>) -> Refusal {
    Refusal::new(
        crate::certificate::code::CERTIFICATE_INVALID,
        exit::VERIFICATION,
        message,
        "plan §6.5 / §13.6 (lot schedule and relief provenance at a retained prefix)",
        "replay the complete certificate in its original book; offline recipients must independently select the account, prefix, cutoff and base unit",
    )
}

fn invalid_request(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §6.5 (the initial certified native-cost lot profile)",
        "certify a debit-normal AnyUnit Asset leaf with dimensionless native-cost history: each acquisition has exactly one quantity debit and one base-currency cost debit, and disposal credits are fully applied; other supported postings remain available in the ordinary advisory lot report",
    )
}

fn bounded(parts: impl IntoIterator<Item = usize>) -> Result<usize, Refusal> {
    let size = parts
        .into_iter()
        .try_fold(0usize, |sum, n| sum.checked_add(n))
        .ok_or_else(|| invalid("lot certificate encoding size overflow"))?;
    if size > MAX_LOTS_CERTIFICATE_BYTES {
        return Err(invalid(
            "complete lot certificate exceeds 64 MiB; no rows were truncated",
        ));
    }
    Ok(size)
}

fn source_account(source: &ReportCertificate) -> Result<VId, Refusal> {
    if source.branch_id != Id128::TRUNK || source.time_selection.is_some() {
        return Err(invalid(
            "lot certificates require a sequence-selected trunk source",
        ));
    }
    match &source.selection {
        ReportSelection::OpenItems {
            account: Some(account),
        } => Ok(*account),
        _ => Err(invalid(
            "lot source must be an all-effective v3 OpenItems certificate selecting exactly one account",
        )),
    }
}

fn amount(w: &mut Writer, amount: Amount) {
    w.u32(amount.unit.0).i128(amount.mantissa);
}

/// Complete, bounded canonical output. The declared currency is part of the
/// bytes; accepting it offline additionally requires a recipient-owned basis.
pub fn lots_output_bytes(report: &LotsReport) -> Result<Vec<u8>, Refusal> {
    if report.lots.len() > MAX_LOTS_ROWS {
        return Err(invalid("lot schedule exceeds its row bound"));
    }
    let mut size = bounded([
        4,
        LOTS_OUTPUT_FORMAT.len(),
        16,
        8,
        1,
        usize::from(report.effective_through.is_some()) * 4,
        16,
        4,
        report.account_code.len(),
        4,
        report.account_name.len(),
        4,
        4,
    ])?;
    let mut applications = 0usize;
    for lot in &report.lots {
        applications = applications
            .checked_add(lot.relieves.len())
            .ok_or_else(|| invalid("lot relief count overflow"))?;
        if applications > MAX_LOTS_ROWS {
            return Err(invalid("lot schedule exceeds its complete relief bound"));
        }
        size = bounded([size, 205])?;
        for relief in &lot.relieves {
            size = bounded([
                size,
                67,
                usize::from(relief.qty_ordinal.is_some()) * 2,
                usize::from(relief.cost_ordinal.is_some()) * 2,
            ])?;
        }
    }
    let mut w = Writer::with_capacity(size);
    w.bytes(LOTS_OUTPUT_FORMAT)
        .fixed(&report.book_id.0)
        .u64(report.known_at.0)
        .opt(report.effective_through.as_ref(), |w, day| {
            w.i32(day.0);
        })
        .u128(report.account.0)
        .str(&report.account_code)
        .str(&report.account_name)
        .u32(report.base_unit.0)
        .list(&report.lots, |w, lot| {
            w.u128(lot.entry.0)
                .fixed(&lot.entry_digest)
                .u16(lot.qty_ordinal)
                .u16(lot.cost_ordinal)
                .u128(lot.account.0)
                .u8(match lot.side {
                    Side::Debit => 0,
                    Side::Credit => 1,
                })
                .i32(lot.effective_date.0)
                .u64(lot.recorded_at.0);
            for value in [
                lot.original_quantity,
                lot.relieved_quantity,
                lot.open_quantity,
                lot.original_cost,
                lot.relieved_cost,
                lot.open_cost,
            ] {
                amount(w, value);
            }
            w.list(&lot.relieves, |w, relief| {
                w.u128(relief.disposal_entry.0)
                    .opt(relief.qty_ordinal.as_ref(), |w, ordinal| {
                        w.u16(*ordinal);
                    })
                    .opt(relief.cost_ordinal.as_ref(), |w, ordinal| {
                        w.u16(*ordinal);
                    });
                amount(w, relief.quantity);
                amount(w, relief.cost);
                w.u64(relief.recorded_at.0).bool(relief.live);
            });
        });
    let bytes = w.finish().map_err(|e| invalid(e.to_string()))?;
    if bytes.len() != size {
        return Err(invalid(
            "lot output size differs from its canonical encoding",
        ));
    }
    Ok(bytes)
}

impl LotsCertificate {
    #[must_use]
    pub fn source(&self) -> &ReportCertificate {
        &self.source
    }
    #[must_use]
    pub fn producer(&self) -> VId {
        self.producer
    }
    #[must_use]
    pub fn capability_commitment(&self) -> &[u8; 32] {
        &self.capability_commitment
    }
    #[must_use]
    pub fn base_unit(&self) -> UnitId {
        self.base_unit
    }
    #[must_use]
    pub fn output(&self) -> &[u8] {
        &self.output
    }
    #[must_use]
    pub fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub fn request(&self) -> Result<LotsRequest, Refusal> {
        Ok(LotsRequest {
            account: source_account(&self.source)?,
            effective_through: self.effective_through,
            known_at: Some(self.source.known_at),
        })
    }

    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        source_account(&self.source)?;
        let source = self
            .source
            .canonical_bytes()
            .map_err(|e| invalid(e.to_string()))?;
        ReportCertificate::decode(&source)?;
        if !source.starts_with(b"fa:report-certificate:v3") {
            return Err(invalid(
                "lot source must retain the v3 native report format",
            ));
        }
        let size = bounded([
            4,
            LOTS_CERTIFICATE_FORMAT.len(),
            16,
            32,
            4,
            source.len(),
            4,
            1,
            usize::from(self.effective_through.is_some()) * 4,
            4,
            self.output.len(),
            32,
        ])?;
        let mut w = Writer::with_capacity(size);
        w.bytes(LOTS_CERTIFICATE_FORMAT)
            .u128(self.producer.0)
            .fixed(&self.capability_commitment)
            .bytes(&source)
            .u32(self.base_unit.0)
            .opt(self.effective_through.as_ref(), |w, day| {
                w.i32(day.0);
            })
            .bytes(&self.output);
        w.finish().map_err(|e| invalid(e.to_string()))
    }

    fn seal(
        source: ReportCertificate,
        report: &LotsReport,
        producer: VId,
        capability_commitment: [u8; 32],
    ) -> Result<Self, Refusal> {
        if report.book_id != source.book_id
            || report.known_at != source.known_at
            || report.account != source_account(&source)?
        {
            return Err(invalid(
                "lot fold and native source name different coordinates",
            ));
        }
        let mut value = Self {
            source,
            base_unit: report.base_unit,
            effective_through: report.effective_through,
            producer,
            capability_commitment,
            output: lots_output_bytes(report)?,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Content integrity only; source history and every acquisition/application
    /// must still replay. This unsigned object is not a disposal-law proof.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut bytes = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&bytes]) != self.digest {
            return Err(invalid("lot certificate digest mismatch"));
        }
        bytes.extend_from_slice(&self.digest);
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        bounded([bytes.len()])?;
        let malformed = |e: DecodeError| invalid(format!("malformed lot certificate: {e}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "lots format").map_err(malformed)? != LOTS_CERTIFICATE_FORMAT {
            return Err(invalid("unsupported lot certificate format"));
        }
        let producer = VId(r.u128("lots producer").map_err(malformed)?);
        let capability_commitment = r.fixed("lots capability").map_err(malformed)?;
        let source = ReportCertificate::decode(
            r.bytes(MAX_LOTS_CERTIFICATE_BYTES, "lots source")
                .map_err(malformed)?,
        )?;
        let base_unit = UnitId(r.u32("lots base unit").map_err(malformed)?);
        let effective_through = r
            .opt("lots cutoff", |r| Ok(DateDay(r.i32("lots cutoff")?)))
            .map_err(malformed)?;
        let output = r
            .bytes(MAX_LOTS_CERTIFICATE_BYTES, "lots output")
            .map_err(malformed)?
            .to_vec();
        let digest = r.fixed("lots digest").map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            base_unit,
            effective_through,
            producer,
            capability_commitment,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical lot certificate"));
        }
        Ok(value)
    }
}

fn authorize<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    principal: VId,
    capability: &Capability,
    known_at: Option<CommitSeq>,
    produce: bool,
) -> Outcome<CommitSeq> {
    let admitted = fa_policy::admit_read(capability, principal, book.context().book_id)
        .and_then(|()| {
            if produce {
                fa_policy::require(
                    capability,
                    Op::Produce,
                    "certifying a historical lot schedule",
                )
            } else {
                Ok(())
            }
        })
        .and_then(|()| {
            fa_policy::reach(
                capability,
                &fa_policy::Reach {
                    observes: known_at.map_or(fa_policy::Observes::Head, fa_policy::Observes::At),
                    ..fa_policy::Reach::whole_book(true)
                },
                None,
            )
        });
    if let Err(denial) = admitted {
        return Ok(Err(fa_journal::policy::refusal(&denial)));
    }
    let query = cx.query();
    query.checkpoint().map_err(BookError::Context)?;
    query.with_restriction(|| {
        let head = book.db.frontier().map_err(KernelError::from)?;
        if let Err(refusal) = fa_journal::policy::current_at(&book.db, book.context(), capability)?
        {
            return Ok(Err(refusal));
        }
        Ok(Ok(head))
    })
}

/// Validate the complete selected account's visible native history, including
/// exhausted and reversed layers and entries after the requested civil cutoff.
/// Other accounts' dimensions and valuations do not change this profile.
fn supported_history(
    entries: &[(VId, Entry, CommitSeq)],
    book: &fa_journal::BookContext,
    account: VId,
    base: UnitId,
) -> Result<(), Refusal> {
    if book
        .units
        .get(base)
        .is_none_or(|u| !matches!(u.kind, UnitKind::Currency { .. }))
    {
        return Err(invalid_request(
            "the retained base unit is not a registered currency",
        ));
    }
    for (vid, entry, _) in entries {
        let legs: Vec<_> = entry
            .proposal
            .legs
            .iter()
            .filter(|leg| leg.account_ref == account)
            .collect();
        if legs.is_empty() {
            continue;
        }
        for leg in &legs {
            if !leg.dimension_set.is_empty() || leg.base_amount.is_some() {
                return Err(invalid_request(format!(
                    "entry {:032x} has dimensions or foreign-valued legs on the selected lot account",
                    vid.0
                )));
            }
            if leg.amount.unit != base
                && book.units.get(leg.amount.unit).is_none_or(|u| {
                    matches!(u.kind, UnitKind::Currency { .. }) || u.allows_single_sided()
                })
            {
                return Err(invalid_request(
                    "lot quantities must be registered balanced noncurrency units",
                ));
            }
        }
        if entry.proposal.class == EntryClass::REVERSAL {
            continue;
        }
        if legs
            .iter()
            .all(|leg| leg.side == Side::Debit && leg.settles.is_empty())
        {
            let quantity: Vec<_> = legs.iter().filter(|leg| leg.amount.unit != base).collect();
            let cost: Vec<_> = legs.iter().filter(|leg| leg.amount.unit == base).collect();
            if quantity.len() != 1
                || cost.len() != 1
                || quantity[0].amount.mantissa <= 0
                || cost[0].amount.mantissa < 0
            {
                return Err(invalid_request(format!(
                    "entry {:032x} does not have exactly one quantity debit and one base-cost debit; multiple acquisition pairs are outside this certificate profile",
                    vid.0
                )));
            }
        } else if legs.iter().all(|leg| leg.side == Side::Credit) {
            for leg in legs {
                let applied = leg
                    .settles
                    .iter()
                    .try_fold(0i128, |sum, settlement| {
                        sum.checked_add(settlement.amount.mantissa)
                    })
                    .ok_or_else(|| invalid_request("lot application sum overflow"))?;
                if leg.amount.mantissa <= 0 || applied != leg.amount.mantissa {
                    return Err(invalid_request(format!(
                        "entry {:032x} contains an unbound or partially applied credit on the selected lot account",
                        vid.0
                    )));
                }
            }
        } else {
            return Err(invalid_request(format!(
                "entry {:032x} mixes acquisition and application sides on the selected lot account",
                vid.0
            )));
        }
    }
    Ok(())
}

pub(crate) fn fold<V: Vfs + Clone, B: Vfs + Clone>(
    book: &AsyncBook<V, B>,
    cx: &PurposeContexts,
    request: &LotsRequest,
) -> Outcome<LotsReport> {
    book.query(cx, |db, context| {
        let at = request.known_at.ok_or_else(|| {
            BookError::Kernel(KernelError::Corrupt(
                "certified lots require a resolved recorded prefix".into(),
            ))
        })?;
        let Some(row) = db
            .vertex_at(request.account, at)
            .map_err(KernelError::from)?
            .filter(|row| row.labels.contains(&label::ACCOUNT))
        else {
            return Ok(Err(invalid_request(
                "the selected lot account does not exist at this prefix",
            )));
        };
        let account = fa_journal::rows::AccountRow::decode(&row)?;
        if account.account_type != AccountType::ASSET.0
            || account.normal_balance != 0
            || !account.is_leaf
            || account.unit_policy != UnitPolicy::AnyUnit
        {
            return Ok(Err(invalid_request(
                "certified lots require a debit-normal AnyUnit Asset posting leaf",
            )));
        }
        let base = fa_journal::genesis::read_book_spec_at(db, at)?
            .ok_or_else(|| KernelError::Corrupt("lot source has no retained book basis".into()))?
            .base_unit;
        let entries = fa_registers::entries_at(db, context, at)?;
        if let Err(refusal) = supported_history(&entries, context, request.account, base) {
            return Ok(Err(refusal));
        }
        let digests: BTreeMap<_, _> = entries
            .iter()
            .map(|(vid, entry, _)| (*vid, entry.entry_digest))
            .collect();
        let items = match request.effective_through {
            Some(day) => fa_registers::open_items::history::open_items_as_of(
                db,
                context,
                Some(request.account),
                day,
                Some(at),
            )
            .map(|snapshot| snapshot.items),
            None => fa_registers::open_items(db, context, Some(request.account), Some(at)),
        };
        let items = match items {
            Ok(items) => items,
            Err(fa_registers::RegisterError::InvalidSelection(message)) => {
                return Ok(Err(invalid_request(message)));
            }
            Err(error) => return Err(error.into()),
        };
        if items.iter().any(|item| !digests.contains_key(&item.entry)) {
            return Ok(Err(invalid(
                "a lot acquisition has no authenticated entry digest",
            )));
        }
        let lots = match fa_registers::lots::fold_lots_from_open_items(&items, &digests, base) {
            Ok(lots) => lots,
            Err(fa_registers::RegisterError::InvalidSelection(message)) => {
                return Ok(Err(invalid_request(message)));
            }
            Err(error) => return Err(error.into()),
        };
        Ok(Ok(LotsReport {
            book_id: context.book_id,
            known_at: at,
            effective_through: request.effective_through,
            account: request.account,
            account_code: account.code,
            account_name: account.name,
            base_unit: base,
            lots,
        }))
    })
}

fn package(
    source: ReportCertificate,
    report: LotsReport,
    principal: VId,
    capability: &Capability,
) -> Result<CertifiedLots, Refusal> {
    let commitment = capability
        .commitment()
        .map_err(|error| invalid(error.to_string()))?;
    let certificate = LotsCertificate::seal(source, &report, principal, commitment)?;
    Ok(CertifiedLots {
        report,
        certificate,
    })
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// Certify the complete native-cost lot schedule without publishing. Read
    /// and Produce authority are current; HEAD resolves once for every input.
    pub fn certify_lots(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        request: &LotsRequest,
    ) -> Outcome<CertifiedLots> {
        let head = match authorize(self, cx, principal, capability, request.known_at, true)? {
            Ok(head) => head,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = request.known_at.unwrap_or(head);
        if at > head {
            return Ok(Err(invalid_request(
                "lot known-at exceeds the observed head",
            )));
        }
        let source = match cx.query().with_restriction(|| {
            crate::certificate::certify_report(
                &self.db,
                cx,
                self.context(),
                ReportSelection::OpenItems {
                    account: Some(request.account),
                },
                Some(at),
            )
        })? {
            Ok(report) => report.certificate,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let fixed = LotsRequest {
            known_at: Some(at),
            ..request.clone()
        };
        let report = match fold(self, cx, &fixed)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = package(source, report, principal, capability);
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Certify the selected account from an existing exact all-effective
    /// OpenItems source. The civil cutoff is applied before lineage netting.
    pub fn certify_lots_from_source(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        source: &ReportCertificate,
        effective_through: Option<DateDay>,
    ) -> Outcome<CertifiedLots> {
        if let Err(refusal) =
            authorize(self, cx, principal, capability, Some(source.known_at), true)?
        {
            return Ok(Err(refusal));
        }
        let account = match source_account(source) {
            Ok(account) => account,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match self.replay_report(cx, source)? {
            Ok(ReportOutput::OpenItems(_)) => {}
            Ok(_) => return Ok(Err(invalid("lot source did not replay as open items"))),
            Err(refusal) => return Ok(Err(refusal)),
        }
        let report = match fold(
            self,
            cx,
            &LotsRequest {
                account,
                effective_through,
                known_at: Some(source.known_at),
            },
        )? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let result = package(source.clone(), report, principal, capability);
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(result)
    }

    /// Recompute acquisition identities, exact open costs and quantities, and
    /// the complete application history. Saved producer metadata grants no
    /// authority; the historical book supplies the actual base currency.
    pub fn replay_lots(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &LotsCertificate,
    ) -> Outcome<LotsReport> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(refusal));
        }
        if let Err(refusal) = certificate.canonical_bytes() {
            return Ok(Err(refusal));
        }
        let request = match certificate.request() {
            Ok(request) => request,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match self.replay_report(cx, &certificate.source)? {
            Ok(ReportOutput::OpenItems(_)) => {}
            Ok(_) => return Ok(Err(invalid("lot source did not replay as open items"))),
            Err(refusal) => return Ok(Err(refusal)),
        }
        let report = match fold(self, cx, &request)? {
            Ok(report) => report,
            Err(refusal) => return Ok(Err(invalid(refusal.message))),
        };
        let output = match lots_output_bytes(&report) {
            Ok(output) => output,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if report.base_unit != certificate.base_unit || output != certificate.output {
            return Ok(Err(invalid(
                "the historical lot schedule or book currency differs from the certificate",
            )));
        }
        cx.query().checkpoint().map_err(BookError::Context)?;
        Ok(Ok(report))
    }

    /// Verify the recipient's original native selection before replay. The
    /// expected sequence must be explicit; HEAD is not a retained expectation.
    pub fn replay_lots_for(
        &self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        certificate: &LotsCertificate,
        expected: &LotsRequest,
    ) -> Outcome<LotsReport> {
        if let Err(refusal) = authorize(
            self,
            cx,
            principal,
            capability,
            Some(certificate.source.known_at),
            false,
        )? {
            return Ok(Err(refusal));
        }
        match certificate.request() {
            Ok(request) if expected.known_at.is_some() && &request == expected => {}
            _ => {
                return Ok(Err(invalid(
                    "lot certificate differs from the independently expected account, prefix or cutoff",
                )));
            }
        }
        self.replay_lots(cx, principal, capability, certificate)
    }
}

#[cfg(test)]
mod tests;
