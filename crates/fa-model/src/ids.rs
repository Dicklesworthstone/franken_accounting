//! Stable handles and derived identities (plan §4.9).
//!
//! Identities are derived, never allocated: the substrate has no key
//! constraints yet (Appendix H R-CON), so uniqueness is enforced by making the
//! vertex identity a function of the business key. A duplicate idempotency key
//! is then a point conflict on one `VId` (`AlreadyLive`), and a retry reads the
//! recorded outcome with one point read. Every derivation is domain-separated
//! and length-prefixes its variable parts, so no two business keys share a
//! transcript.

use core::fmt;

use fgdb_crypto::Hasher;
use fgdb_types::VId;

use crate::canon::{DecodeError, Reader, Writer};
use crate::limits::MAX_PERIOD_REF_BYTES;

/// A 128-bit opaque identity (`book_id`, `branch_id`).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id128(pub [u8; 16]);

impl Id128 {
    /// The trunk branch of every book.
    pub const TRUNK: Self = Self([0u8; 16]);

    #[must_use]
    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl fmt::Debug for Id128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Id128({})", self.to_hex())
    }
}

/// A substrate content-addressed object identity.
pub use fgdb_types::ObjectId as Oid;

/// A self-verifying handle to a committed entry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntryRef {
    pub vid: VId,
    pub entry_digest: [u8; 32],
}

impl EntryRef {
    pub fn encode(&self, w: &mut Writer) {
        w.u128(self.vid.0).fixed(&self.entry_digest);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            vid: VId(r.u128("entry_ref.vid")?),
            entry_digest: r.fixed("entry_ref.entry_digest")?,
        })
    }
}

/// An approval in the committed transcript: it binds the *proposal* digest,
/// never the envelope's own digest (plan §4.6, acyclic by construction).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ApprovalRef {
    pub approval_vid: VId,
    pub approved_digest: [u8; 32],
}

impl ApprovalRef {
    pub fn encode(&self, w: &mut Writer) {
        w.u128(self.approval_vid.0).fixed(&self.approved_digest);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            approval_vid: VId(r.u128("approval.vid")?),
            approved_digest: r.fixed("approval.digest")?,
        })
    }
}

/// `{ calendar, code }` — the period handle agents cite (`FY2026-P03`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PeriodRef {
    pub calendar: String,
    pub code: String,
}

impl PeriodRef {
    pub fn encode(&self, w: &mut Writer) {
        w.str(&self.calendar).str(&self.code);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        Ok(Self {
            calendar: r
                .str(MAX_PERIOD_REF_BYTES, "period_ref.calendar")?
                .to_string(),
            code: r.str(MAX_PERIOD_REF_BYTES, "period_ref.code")?.to_string(),
        })
    }

    #[must_use]
    pub fn within_bounds(&self) -> bool {
        self.calendar.len() <= MAX_PERIOD_REF_BYTES && self.code.len() <= MAX_PERIOD_REF_BYTES
    }
}

/// A tagged reference to a vertex or a content-addressed object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TypedRef {
    Vertex(VId),
    Object(Oid),
}

impl TypedRef {
    pub fn encode(&self, w: &mut Writer) {
        match self {
            Self::Vertex(v) => {
                w.u8(0).u128(v.0);
            }
            Self::Object(o) => {
                w.u8(1).fixed(&o.0);
            }
        }
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, DecodeError> {
        match r.u8("typed_ref.tag")? {
            0 => Ok(Self::Vertex(VId(r.u128("typed_ref.vid")?))),
            1 => Ok(Self::Object(Oid(r.fixed("typed_ref.oid")?))),
            t => Err(r.bad_tag("typed_ref.tag", t)),
        }
    }
}

/// `BLAKE3(domain ‖ parts…)` with every part `u32`-length-prefixed, truncated
/// to the substrate's 128-bit vertex identity.
fn derive_vid(domain: &[u8], parts: &[&[u8]]) -> VId {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        // A part longer than u32::MAX bytes cannot arise from a validated
        // payload; saturating keeps the transcript total rather than silent.
        let n = u32::try_from(p.len()).unwrap_or(u32::MAX);
        h.update(&n.to_le_bytes());
        h.update(p);
    }
    let d = h.finalize();
    let mut lo = [0u8; 16];
    lo.copy_from_slice(&d.0[..16]);
    VId(u128::from_le_bytes(lo))
}

/// `vid(Entry) = H("fa:vid:entry:v1" ‖ book_id ‖ principal_scope ‖ idempotency_key)`.
#[must_use]
pub fn entry_vid(book: Id128, principal_scope: &[u8], idempotency_key: &[u8]) -> VId {
    derive_vid(
        b"fa:vid:entry:v1",
        &[&book.0, principal_scope, idempotency_key],
    )
}

/// `vid(IntentOutcome) = H("fa:vid:intent-outcome:v1" ‖ book ‖
/// principal_scope ‖ key)` (plan §5.9): a common successful-intent namespace
/// for ordinary posts, target-derived corrections/resolutions, and atomic
/// batches. Entry identity separately enforces its target uniqueness law;
/// every covered writer reserves this point atomically with its entries.
#[must_use]
pub fn intent_outcome_vid(book: Id128, principal_scope: &[u8], idempotency_key: &[u8]) -> VId {
    derive_vid(
        b"fa:vid:intent-outcome:v1",
        &[&book.0, principal_scope, idempotency_key],
    )
}

/// `vid(MigrationRun) = H("fa:vid:migration-run:v1" ‖ book_id ‖ run_key)`
/// (plan §8.6): one run per key, so a retry is a new run under a new key.
#[must_use]
pub fn migration_run_vid(book: Id128, run_key: &str) -> VId {
    derive_vid(b"fa:vid:migration-run:v1", &[&book.0, run_key.as_bytes()])
}

/// `vid(DraftSet) = H("fa:vid:draft:v1" ‖ book ‖ name)` (plan §15.2,
/// bead fa-s7x): one draft per name in a book.
#[must_use]
pub fn draft_vid(book: Id128, name: &str) -> VId {
    derive_vid(b"fa:vid:draft:v1", &[&book.0, name.as_bytes()])
}

/// `vid(Scenario) = H("fa:vid:scenario:v1" ‖ book ‖ name)` (plan §15.2,
/// bead fa-k07b): one scenario per name in a book.
#[must_use]
pub fn scenario_vid(book: Id128, name: &str) -> VId {
    derive_vid(b"fa:vid:scenario:v1", &[&book.0, name.as_bytes()])
}

/// `vid(ProductionProfile) = H("fa:vid:production-profile:v1" ‖ book ‖
/// matter)` (plan §13.2, bead fa-6l9): one profile per matter in a book.
#[must_use]
pub fn production_profile_vid(book: Id128, matter: &str) -> VId {
    derive_vid(
        b"fa:vid:production-profile:v1",
        &[&book.0, matter.as_bytes()],
    )
}

/// `vid(Engagement) = H("fa:vid:engagement:v1" ‖ book ‖ engagement)` (plan
/// §11.12, bead fa-zgn): one engagement per id in a book.
#[must_use]
pub fn engagement_vid(book: Id128, engagement: &str) -> VId {
    derive_vid(b"fa:vid:engagement:v1", &[&book.0, engagement.as_bytes()])
}

/// `vid(ProposedAdjustment) = H("fa:vid:proposed-adjustment:v1" ‖ book ‖
/// engagement ‖ ordinal)` (bead fa-zgn): an engagement's proposals are
/// numbered from 1 in the order they are journaled.
#[must_use]
pub fn proposed_adjustment_vid(book: Id128, engagement: &str, ordinal: u32) -> VId {
    derive_vid(
        b"fa:vid:proposed-adjustment:v1",
        &[&book.0, engagement.as_bytes(), &ordinal.to_le_bytes()],
    )
}

/// `vid(BatesRange) = H("fa:vid:bates-range:v1" ‖ book ‖ matter ‖ oid)`
/// (bead fa-6l9): a document's one Bates range in a matter, so producing it
/// again in that matter never burns new numbers.
#[must_use]
pub fn bates_range_vid(book: Id128, matter: &str, document: &Oid) -> VId {
    derive_vid(
        b"fa:vid:bates-range:v1",
        &[&book.0, matter.as_bytes(), &document.0],
    )
}

/// `vid(AccessEvent) = H("fa:vid:access-event:v1" ‖ book ‖ payload digest)`
/// (plan §9.7, bead fa-7dw): one record per served read. The payload names
/// the head the read observed, which every recorded event advances, so two
/// reads never share an identity.
#[must_use]
pub fn access_event_vid(book: Id128, digest: &[u8; 32]) -> VId {
    derive_vid(b"fa:vid:access-event:v1", &[&book.0, digest])
}

/// `vid(Certificate) = H("fa:vid:report-certificate:v1" ‖ book ‖ digest)`:
/// where a book retains the report certificate with this public digest.
/// The complete digest remains mandatory when reading the located vertex.
#[must_use]
pub fn report_certificate_vid(book: Id128, digest: &[u8; 32]) -> VId {
    derive_vid(b"fa:vid:report-certificate:v1", &[&book.0, digest])
}

/// `vid(StatementIssuance) = H("fa:vid:statement-issuance:v1" ‖ book ‖
/// period ‖ u32 ordinal)` (plan §12.5, bead fa-wrrw): a period's issuances
/// are numbered from 1 in commit order, so its first issuance, the one `AS
/// ORIGINALLY REPORTED` reads, is one point read.
#[must_use]
pub fn statement_issuance_vid(book: Id128, period: &str, ordinal: u32) -> VId {
    derive_vid(
        b"fa:vid:statement-issuance:v1",
        &[&book.0, period.as_bytes(), &ordinal.to_le_bytes()],
    )
}

/// `vid(RestatementCase) = H("fa:vid:case:v1" ‖ book ‖ u32 ordinal)` (plan
/// §8.3, bead fa-75j4): a book's cases are numbered from 1 in commit order.
#[must_use]
pub fn restatement_case_vid(book: Id128, ordinal: u32) -> VId {
    derive_vid(b"fa:vid:case:v1", &[&book.0, &ordinal.to_le_bytes()])
}

/// `vid(Entry) = H("fa:vid:migration-entry:v1" ‖ book_id ‖ run ‖
/// idempotency_key)` for a `Migration` entry (plan §8.6): the run is part of
/// the identity, so a retry run reuses the abandoned run's keys.
#[must_use]
pub fn migration_entry_vid(book: Id128, run: VId, idempotency_key: &[u8]) -> VId {
    derive_vid(
        b"fa:vid:migration-entry:v1",
        &[&book.0, &run.0.to_le_bytes(), idempotency_key],
    )
}

/// `vid(ExternalId) = H("fa:vid:extid:v1" ‖ book_id ‖ system ‖ id)`.
#[must_use]
pub fn external_id_vid(book: Id128, system: &str, id: &str) -> VId {
    derive_vid(
        b"fa:vid:extid:v1",
        &[&book.0, system.as_bytes(), id.as_bytes()],
    )
}

/// `vid(Account) = H("fa:vid:account:v1" ‖ book_id ‖ code)`.
#[must_use]
pub fn account_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:account:v1", &[&book.0, code.as_bytes()])
}

/// `vid(Period) = H("fa:vid:period:v1" ‖ calendar_id ‖ code)`.
#[must_use]
pub fn period_vid(calendar: &str, code: &str) -> VId {
    derive_vid(b"fa:vid:period:v1", &[calendar.as_bytes(), code.as_bytes()])
}

/// `vid(Unit) = H("fa:vid:unit:v1" ‖ book_id ‖ unit_code)`.
#[must_use]
pub fn unit_vid(book: Id128, unit_code: &str) -> VId {
    derive_vid(b"fa:vid:unit:v1", &[&book.0, unit_code.as_bytes()])
}

/// The dimension id of a book's legal-entity dimension (plan §4.1 Dimension
/// row, §5.2): the balancing dimension a leg's `dimension_set` carries its
/// legal entity in.
pub const LEGAL_ENTITY_DIMENSION: u32 = 1;

/// The code of a book's legal-entity dimension.
pub const LEGAL_ENTITY_DIMENSION_CODE: &str = "legal_entity";

/// `vid(LegalEntity) = H("fa:vid:legal-entity:v1" ‖ book_id ‖ code)`.
#[must_use]
pub fn legal_entity_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:legal-entity:v1", &[&book.0, code.as_bytes()])
}

/// `vid(Dimension) = H("fa:vid:dimension:v1" ‖ book_id ‖ dimension_code)`.
#[must_use]
pub fn dimension_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:dimension:v1", &[&book.0, code.as_bytes()])
}

/// `vid(DimensionValue) = H("fa:vid:dimension-value:v1" ‖ book_id ‖
/// dimension_code ‖ value_code)`: what a leg's `dimension_set` references.
#[must_use]
pub fn dimension_value_vid(book: Id128, dimension_code: &str, value_code: &str) -> VId {
    derive_vid(
        b"fa:vid:dimension-value:v1",
        &[&book.0, dimension_code.as_bytes(), value_code.as_bytes()],
    )
}

/// `vid(RuleVersion) = H("fa:vid:rule-version:v1" ‖ book_id ‖ ir_digest)`:
/// a Canon rule version is addressed by its content (plan §10.3).
#[must_use]
pub fn rule_version_vid(book: Id128, ir_digest: &[u8; 32]) -> VId {
    derive_vid(b"fa:vid:rule-version:v1", &[&book.0, ir_digest])
}

/// The `dimension_set` value of legal entity `code` in `book`.
#[must_use]
pub fn entity_value_vid(book: Id128, code: &str) -> VId {
    dimension_value_vid(book, LEGAL_ENTITY_DIMENSION_CODE, code)
}

/// The dimension id of a book's party dimension (plan §4.1 `Dimension` /
/// `Party`, bead `fa-l2h`): non-balancing counterparty dimension (`label::PARTY` = 12).
pub const PARTY_DIMENSION: u32 = 12;

/// The code of a book's party dimension.
pub const PARTY_DIMENSION_CODE: &str = "party";

/// `vid(Party) = H("fa:vid:party:v1" ‖ book_id ‖ code)` (plan §4.5, §4.9).
#[must_use]
pub fn party_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:party:v1", &[&book.0, code.as_bytes()])
}

/// The `dimension_set` value of party `code` in `book`.
#[must_use]
pub fn party_value_vid(book: Id128, code: &str) -> VId {
    dimension_value_vid(book, PARTY_DIMENSION_CODE, code)
}

/// A registered dimension kind whose values a book creates with
/// `fa dimension add` (plan §4.1 `Dimension.kind`, bead fa-ficc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DimensionKind {
    /// The dimension's code, which is also its kind's name.
    pub code: &'static str,
    /// The fixed dimension id a leg's `dimension_set` carries its values under.
    pub id: u32,
    /// The `dimension_kind` tag of its Dimension vertex.
    pub tag: i64,
}

/// The registered dimension kinds besides the legal entity (id 1, created
/// at genesis) and the party (id 12, created by `fa party add`). A book has
/// at most one dimension of each kind, so the kind fixes its id; none of
/// them balances. Ids ascend in this order, as a `dimension_set` does.
pub const DIMENSION_KINDS: [DimensionKind; 8] = [
    DimensionKind {
        code: "cost_center",
        id: 2,
        tag: 3,
    },
    DimensionKind {
        code: "department",
        id: 3,
        tag: 4,
    },
    DimensionKind {
        code: "project",
        id: 4,
        tag: 5,
    },
    DimensionKind {
        code: "product",
        id: 5,
        tag: 6,
    },
    DimensionKind {
        code: "region",
        id: 6,
        tag: 7,
    },
    DimensionKind {
        code: "fund",
        id: 7,
        tag: 8,
    },
    DimensionKind {
        code: "grant",
        id: 8,
        tag: 9,
    },
    DimensionKind {
        code: "segment",
        id: 9,
        tag: 10,
    },
];

/// The registered kind named `code`.
#[must_use]
pub fn dimension_kind(code: &str) -> Option<DimensionKind> {
    DIMENSION_KINDS.into_iter().find(|kind| kind.code == code)
}

/// The registered kind whose values carry dimension id `id`.
#[must_use]
pub fn dimension_kind_of(id: u32) -> Option<DimensionKind> {
    DIMENSION_KINDS.into_iter().find(|kind| kind.id == id)
}

/// `vid(Instrument) = H("fa:vid:instrument:v1" ‖ book_id ‖ code)` (plan §4.5, §4.9).
#[must_use]
pub fn instrument_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:instrument:v1", &[&book.0, code.as_bytes()])
}

/// `vid(Event) = H("fa:vid:event:v1" ‖ book_id ‖ code)` (plan §4.1 `Event`, §4.5, §4.9, bead `fa-f3bo`).
#[must_use]
pub fn event_vid(book: Id128, code: &str) -> VId {
    derive_vid(b"fa:vid:event:v1", &[&book.0, code.as_bytes()])
}

/// `vid(Principal) = H("fa:vid:principal:v1" ‖ name)`: the identity a
/// named operator or agent posts under until Steward issues principals.
#[must_use]
pub fn principal_vid(name: &str) -> VId {
    derive_vid(b"fa:vid:principal:v1", &[name.as_bytes()])
}

/// `BLAKE3(domain ‖ len(part) ‖ part …)`: the one way FrankenAccounting
/// derives a public identity from parts, so no surviving public digest is
/// ever an unkeyed hash of a raw request.
#[must_use]
pub fn domain_digest(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(domain);
    for p in parts {
        let n = u32::try_from(p.len()).unwrap_or(u32::MAX);
        h.update(&n.to_le_bytes());
        h.update(p);
    }
    h.finalize().0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derived_identities_are_deterministic_and_domain_separated() {
        let book = Id128([7; 16]);
        assert_eq!(entry_vid(book, b"p", b"k1"), entry_vid(book, b"p", b"k1"));
        assert_ne!(entry_vid(book, b"p", b"k1"), entry_vid(book, b"p", b"k2"));
        assert_ne!(
            entry_vid(book, b"p", b"k1"),
            entry_vid(Id128([8; 16]), b"p", b"k1")
        );
        // Length prefixes: ("ab","c") and ("a","bc") are different keys.
        assert_ne!(
            external_id_vid(book, "ab", "c"),
            external_id_vid(book, "a", "bc")
        );
        // Domains: an account and a unit with the same code differ.
        assert_ne!(account_vid(book, "USD"), unit_vid(book, "USD"));
        assert_ne!(
            period_vid("cal", "FY2026-P01"),
            period_vid("cal", "FY2026-P02")
        );
        // An entity, its dimension value, and the dimension are distinct.
        assert_ne!(legal_entity_vid(book, "A"), entity_value_vid(book, "A"));
        assert_ne!(entity_value_vid(book, "A"), entity_value_vid(book, "B"));
        assert_ne!(
            dimension_value_vid(book, "legal_entity", "A"),
            dimension_value_vid(book, "legal_entityA", "")
        );
    }

    /// The legal-entity identities are durable formats: pinned by fixed
    /// vectors so neither a domain nor a part order can drift.
    #[test]
    fn legal_entity_identities_are_fixed_vectors() {
        let book = Id128([1; 16]);
        assert_eq!(
            entity_value_vid(book, "A"),
            dimension_value_vid(book, LEGAL_ENTITY_DIMENSION_CODE, "A")
        );
        assert_eq!(
            legal_entity_vid(book, "A"),
            VId(0x49e8_d274_2d3f_58a5_620b_c8a6_1641_bc35)
        );
        assert_eq!(
            dimension_vid(book, LEGAL_ENTITY_DIMENSION_CODE),
            VId(0x8d62_bd8e_6d0d_4a82_b970_32a9_91c3_b236)
        );
        assert_eq!(
            entity_value_vid(book, "A"),
            VId(0x706e_3a84_7465_5d79_9778_0326_7661_5406)
        );
    }

    /// Durable identities (plan §8.6): pinned so a change to the domain, the
    /// part order, or the run's byte form fails here, not in a migrated book.
    #[test]
    fn migration_identities_are_pinned() {
        let book = Id128([1; 16]);
        let run = migration_run_vid(book, "go-live");
        assert_eq!(run, VId(0x234a_61ec_52cd_c6a7_442d_0c1f_8c35_b825));
        assert_eq!(
            migration_entry_vid(book, run, b"open-1"),
            VId(0xe0bc_098e_ed09_c0e6_898e_5de2_fc90_db2c)
        );
        // The run is part of an entry's identity; the key alone is not.
        assert_ne!(
            migration_entry_vid(book, run, b"open-1"),
            migration_entry_vid(book, migration_run_vid(book, "retry"), b"open-1")
        );
        assert_ne!(
            migration_entry_vid(book, run, b"open-1"),
            entry_vid(book, &run.0.to_le_bytes(), b"open-1")
        );
    }

    #[test]
    fn handles_round_trip() {
        let e = EntryRef {
            vid: VId(42),
            entry_digest: [3; 32],
        };
        let a = ApprovalRef {
            approval_vid: VId(9),
            approved_digest: [4; 32],
        };
        let p = PeriodRef {
            calendar: "cal".into(),
            code: "FY2026-P01".into(),
        };
        let t = [TypedRef::Vertex(VId(1)), TypedRef::Object(Oid([5; 32]))];
        let mut w = Writer::new();
        e.encode(&mut w);
        a.encode(&mut w);
        p.encode(&mut w);
        for x in &t {
            x.encode(&mut w);
        }
        let b = w.finish().unwrap();
        let mut r = Reader::new(&b);
        assert_eq!(EntryRef::decode(&mut r).unwrap(), e);
        assert_eq!(ApprovalRef::decode(&mut r).unwrap(), a);
        assert_eq!(PeriodRef::decode(&mut r).unwrap(), p);
        assert_eq!(TypedRef::decode(&mut r).unwrap(), t[0]);
        assert_eq!(TypedRef::decode(&mut r).unwrap(), t[1]);
        r.finish().unwrap();
        assert!(TypedRef::decode(&mut Reader::new(&[9])).is_err());
        assert_eq!(
            format!("{:?}", Id128::TRUNK),
            format!("Id128({})", "0".repeat(32))
        );
    }
}
