//! Evidence-bound native allocation posting (plan §6.3; fa-joq).
//!
//! A fixed, explicit amount is redistributed from one source account across
//! caller-ordered target accounts in one unit and one shared dimension set.
//! The source side is explicit. Negative pro-rata corrections swap the target
//! side; zero shares remain in the basis but do not create zero-valued legs.
//! This is not a fold-derived balance sweep, FX valuation, settlement or Canon.
//!
//! The basis is an ordinary Workpaper document. Its exact canonical bytes,
//! law digest and basis digest also ride extension 5 of an entry at minor 2.
//! Every leg inherits that binding through its containing proposal. The core
//! entry codec preserves additive extensions; this module interprets this
//! extension in full. Older kernels still refuse the Allocation class.
//! The native posting pipeline checks the computed legs before staging and
//! resolves the exact driver citation in its ordinary evidence transaction.

use fa_model::limits::{MAX_DIMENSIONS_PER_LEG, MAX_EXTENSION_BYTES};
use fa_model::symbols::label;
use fa_model::{EntryClass, EntryOrigin, EntryPayload, EvidenceRef, Id128, LegPayload, Reader, Writer, domain_digest};
use fa_money::allocation::{AllocationCatalog, AllocationOutcome, AllocationRequest, MAX_ALLOCATION_REQUEST_BYTES};
use fa_money::{Amount, Side, UnitKind};
use fgdb::{Database, WriteTxn};
use fgdb_types::VId;

use crate::evidence::{doc_commit, document_oid};
use crate::genesis::{BookContext, UnitPolicy};
use crate::refusal::{Outcome, Refusal, code, exit};
use crate::rows::AccountRow;

pub const ALLOCATION_EXTENSION: u16 = 5;
pub const ALLOCATION_SCHEMA_MINOR: u16 = 2;
pub const ALLOCATION_DOCUMENT_KIND: u8 = 21; // Workpaper
pub const ALLOCATION_EVIDENCE_ROLE: u8 = 1; // Source
/// This posting format also has to fit the existing 64 KiB extension bound.
pub const MAX_POSTING_TARGETS: usize = 1024;
const BASIS_MAGIC: &[u8; 15] = b"FA-ALLOC-BASIS\0";
const RECORD_MAGIC: &[u8; 14] = b"FA-ALLOC-POST\0";

/// The target identities in `request` are actual account VIds. Each account
/// occurs once. All legs use the same explicitly supplied dimensions, which
/// the existing entity/dimension admission still judges. No account, side,
/// unit, amount or allocation driver is inferred from a current balance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AllocationPosting {
    pub source: VId,
    pub source_side: Side,
    pub dimensions: Vec<(u32, VId)>,
    pub request: AllocationRequest,
}

impl AllocationPosting {
    fn validate_shape(&self) -> Result<(), Refusal> {
        self.request.validate_shape(&AllocationCatalog::embedded().map_err(structure)?)
            .map_err(structure)?;
        if self.request.total.mantissa <= 0 || self.request.targets.len() > MAX_POSTING_TARGETS {
            return Err(structure("posting requires a positive explicit total and at most 1024 targets"));
        }
        if self.request.targets.iter().any(|target| target.id == self.source.0) {
            return Err(structure("an allocation target cannot be its source account"));
        }
        if self.dimensions.len() > MAX_DIMENSIONS_PER_LEG
            || self.dimensions.windows(2).any(|pair| pair[0].0 >= pair[1].0)
        {
            return Err(structure("dimensions must be distinct and ordered by dimension id"));
        }
        Ok(())
    }

    /// Exact driver-document bytes. The caller imports these as a Workpaper
    /// with its actual uploader/grade; this does not invent provenance or I/O.
    pub fn basis_bytes(&self) -> Result<Vec<u8>, Refusal> {
        self.validate_shape()?;
        let request = self.request.canonical_bytes().map_err(structure)?;
        let mut w = Writer::new();
        w.fixed(BASIS_MAGIC).u16(1).u128(self.source.0)
            .u8(side_tag(self.source_side))
            .list(&self.dimensions, |w, (dimension, value)| {
                w.u32(*dimension).u128(value.0);
            }).bytes(&request);
        let bytes = w.finish().map_err(structure)?;
        // The record adds its magic/version, length, and two digests.
        if bytes.len().checked_add(84).is_none_or(|len| len > MAX_EXTENSION_BYTES) {
            return Err(structure("allocation basis exceeds the entry extension bound"));
        }
        Ok(bytes)
    }

    pub fn basis_digest(&self) -> Result<[u8; 32], Refusal> {
        Ok(domain_digest(b"fa:allocation-basis:v1", &[&self.basis_bytes()?]))
    }

    /// A registry identity, not a claim that a native object store holds it.
    /// Changing an executable law requires a new version and hence a new digest.
    pub fn law_digest(&self) -> [u8; 32] {
        let law = self.request.method.law();
        domain_digest(b"fa:allocation-law:v1", &[&law.id().to_le_bytes(), &law.version().to_le_bytes()])
    }

    pub fn driver_evidence(&self, book: Id128) -> Result<EvidenceRef, Refusal> {
        let commitment = doc_commit(ALLOCATION_DOCUMENT_KIND, &self.basis_bytes()?);
        Ok(EvidenceRef {
            document_oid: document_oid(book, &commitment),
            doc_commit: commitment,
            role: ALLOCATION_EVIDENCE_ROLE,
        })
    }

    fn decode_basis(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(structure("allocation basis exceeds its byte bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<15>("allocation.basis.magic").map_err(structure)? != *BASIS_MAGIC
            || r.u16("allocation.basis.version").map_err(structure)? != 1
        {
            return Err(structure("unsupported allocation basis format"));
        }
        let source = VId(r.u128("allocation.source").map_err(structure)?);
        let source_side = match r.u8("allocation.source_side").map_err(structure)? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => return Err(structure("unknown allocation source side")),
        };
        let dimensions = r.list(MAX_DIMENSIONS_PER_LEG, "allocation.dimensions", |r| {
            Ok((r.u32("allocation.dimension")?, VId(r.u128("allocation.dimension_value")?)))
        }).map_err(structure)?;
        let request = AllocationRequest::decode(
            r.bytes(MAX_ALLOCATION_REQUEST_BYTES, "allocation.request").map_err(structure)?,
        ).map_err(structure)?;
        r.finish().map_err(structure)?;
        let basis = Self { source, source_side, dimensions, request };
        if basis.basis_bytes()?.as_slice() != bytes {
            return Err(structure("allocation basis is not canonical"));
        }
        Ok(basis)
    }

    fn record_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let basis = self.basis_bytes()?;
        let mut w = Writer::new();
        w.fixed(RECORD_MAGIC).u16(1).bytes(&basis).fixed(&self.law_digest())
            .fixed(&domain_digest(b"fa:allocation-basis:v1", &[&basis]));
        let bytes = w.finish().map_err(structure)?;
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(structure("allocation record exceeds the entry extension bound"));
        }
        Ok(bytes)
    }

    fn decode_record(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_EXTENSION_BYTES {
            return Err(structure("allocation record exceeds the entry extension bound"));
        }
        let mut r = Reader::new(bytes);
        if r.fixed::<14>("allocation.record.magic").map_err(structure)? != *RECORD_MAGIC
            || r.u16("allocation.record.version").map_err(structure)? != 1
        {
            return Err(structure("unsupported allocation record format"));
        }
        let basis = Self::decode_basis(r.bytes(MAX_EXTENSION_BYTES, "allocation.basis").map_err(structure)?)?;
        let law_digest = r.fixed::<32>("allocation.law_digest").map_err(structure)?;
        let basis_digest = r.fixed::<32>("allocation.basis_digest").map_err(structure)?;
        r.finish().map_err(structure)?;
        if law_digest != basis.law_digest() || basis_digest != basis.basis_digest()? {
            return Err(structure("allocation law or basis digest does not recompute"));
        }
        Ok(basis)
    }

    fn legs(&self, outcome: &AllocationOutcome) -> Result<Vec<LegPayload>, Refusal> {
        let mut legs = Vec::new();
        legs.try_reserve_exact(self.request.targets.len() + 1).map_err(structure)?;
        let mut source = LegPayload::simple(self.source_side, self.source, self.request.total);
        source.dimension_set = self.dimensions.clone();
        legs.push(source);
        for (target, share) in self.request.targets.iter().zip(outcome.shares()) {
            if share.mantissa == 0 {
                continue;
            }
            let magnitude = i128::try_from(share.mantissa.unsigned_abs()).map_err(structure)?;
            let side = if share.mantissa < 0 { self.source_side } else { opposite(self.source_side) };
            let mut leg = LegPayload::simple(side, VId(target.id), Amount::new(share.unit, magnitude));
            leg.dimension_set = self.dimensions.clone();
            legs.push(leg);
        }
        Ok(legs)
    }

    /// Fill an explicitly Allocation-class, empty-leg proposal. Coordinates,
    /// principal, evidence, sealed description, and other caller metadata are
    /// preserved. Existing effects are refused rather than silently replaced.
    /// The caller must already cite the exact imported driver Workpaper.
    pub fn proposal(&self, mut template: EntryPayload) -> Result<EntryPayload, Refusal> {
        if template.class != EntryClass::ALLOCATION
            || !matches!(&template.origin, EntryOrigin::Intent { .. })
            || template.schema_minor > ALLOCATION_SCHEMA_MINOR
            || !template.legs.is_empty() || !template.unit_totals.is_empty()
            || !template.extensions.is_empty() || template.control.is_some()
            || template.base_totals.is_some() || template.pending.is_some()
            || !template.supersession.is_empty()
        {
            return Err(structure("use an Allocation Intent template with no existing legs, totals, extensions or lifecycle effects"));
        }
        self.validate_shape()?;
        self.check_driver(&template)?;
        let outcome = self.request.execute().map_err(structure)?;
        template.legs = self.legs(&outcome)?;
        template.unit_totals = EntryPayload::fold_unit_totals(&template.legs).map_err(structure)?;
        template.schema_minor = ALLOCATION_SCHEMA_MINOR;
        template.extensions = vec![(ALLOCATION_EXTENSION, self.record_bytes()?)];
        template.validate().map_err(structure)?;
        Ok(template)
    }

    fn check_driver(&self, proposal: &EntryPayload) -> Result<(), Refusal> {
        let expected = self.driver_evidence(proposal.book_id)?;
        if !proposal.evidence.contains(&expected) {
            return Err(Refusal::new(
                code::EVIDENCE_COMMIT, exit::REFUSAL,
                "allocation does not cite the exact canonical driver Workpaper as Source evidence",
                "plan §6.3, FA-INV-05 (allocation driver commitment)",
                "import AllocationPosting::basis_bytes as a Workpaper, cite driver_evidence(book_id), and build a fresh proposal",
            ));
        }
        Ok(())
    }
}

/// Enforce this extension on every public posting path, not just the typed
/// constructor. An unknown/corrupted body cannot be made valid by repairing
/// its outer entry digest or balancing its totals. This does no storage reads.
pub(crate) fn admit(proposal: &EntryPayload) -> Result<Option<AllocationPosting>, Refusal> {
    let record = proposal.extensions.iter().find(|(tag, _)| *tag == ALLOCATION_EXTENSION);
    if proposal.class != EntryClass::ALLOCATION {
        return if record.is_some() {
            Err(structure("allocation provenance belongs only on Allocation entries"))
        } else { Ok(None) };
    }
    let Some((_, bytes)) = record else {
        return Err(Refusal::new(
            code::CLASS_NOT_IMPLEMENTED, exit::REFUSAL,
            "an Allocation without its registered computation basis is not admitted",
            "plan §6.3 (recompute the registered law and driver basis)",
            "construct the proposal with AllocationPosting::proposal; raw balanced legs are insufficient",
        ));
    };
    if proposal.schema_minor != ALLOCATION_SCHEMA_MINOR || proposal.extensions.len() != 1 {
        return Err(structure("allocation requires exactly its minor-2 computation extension"));
    }
    let basis = AllocationPosting::decode_record(bytes)?;
    basis.check_driver(proposal)?;
    let outcome = basis.request.execute().map_err(structure)?;
    if proposal.legs != basis.legs(&outcome)? {
        return Err(structure("allocation legs do not exactly reproduce the registered law and basis"));
    }
    Ok(Some(basis))
}

/// Every declared target, including one receiving zero, must resolve to a
/// valid leaf in the posting transaction. Omitting zero-valued legs must not
/// let a nonexistent/summary/wrong-unit target escape account admission.
pub(crate) fn witness_targets<V: asupersync::fs::Vfs + Clone>(
    txn: &WriteTxn, db: &Database<V>, book: &BookContext, basis: &AllocationPosting,
) -> Outcome<()> {
    let unit = basis.request.total.unit;
    for target in &basis.request.targets {
        let row = match txn.vertex(db, VId(target.id))? {
            Some(row) if row.labels.contains(&label::ACCOUNT) => row,
            _ => return Ok(Err(Refusal::new(
                code::UNKNOWN_ACCOUNT, exit::REFUSAL,
                format!("allocation target {:032x} is not an account in this book", target.id),
                "plan §4.3, §6.3 (all declared allocation targets resolve)",
                "use fa chart list --json and rebuild the driver with existing leaf accounts",
            ))),
        };
        let account = AccountRow::decode(&row)?;
        if !account.is_leaf {
            return Ok(Err(Refusal::new(
                code::NOT_A_LEAF, exit::REFUSAL,
                format!("allocation target {} is a summary account", account.code),
                "plan §4.3 (allocation targets are leaves, even for zero shares)",
                "choose leaf accounts and prepare the driver again",
            )));
        }
        let compatible = book.units.get(unit).is_some_and(|registered| match account.unit_policy {
            UnitPolicy::Single(only) => only == unit,
            UnitPolicy::AnyCurrency => matches!(registered.kind, UnitKind::Currency { .. }),
            UnitPolicy::AnyUnit => true,
        });
        if !compatible {
            return Ok(Err(Refusal::new(
                code::UNIT_POLICY, exit::REFUSAL,
                format!("allocation target {} does not accept registered unit {}", account.code, unit.0),
                "plan §4.3, §6.3 (native-unit allocation; no implicit FX)",
                "select a registered unit accepted by every source and target account",
            )));
        }
    }
    Ok(Ok(()))
}

fn side_tag(side: Side) -> u8 { match side { Side::Debit => 0, Side::Credit => 1 } }
fn opposite(side: Side) -> Side { match side { Side::Debit => Side::Credit, Side::Credit => Side::Debit } }
fn structure(error: impl core::fmt::Display) -> Refusal {
    Refusal::new(code::STRUCTURE, exit::USAGE, format!("allocation: {error}"),
        "plan §6.3, fa:allocation-posting:v1",
        "correct the explicit source, native total, ordered targets, dimensions and registered law; rebuild the driver and proposal")
}

#[cfg(test)]
mod tests;
