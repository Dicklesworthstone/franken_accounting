use fa_model::symbols::property;
use fa_model::{DecodeError, EntryRef, Id128, Oid, Reader, Writer, domain_digest};
use fa_money::{Amount, Side, UnitId};
use fa_policy::{Capability, DecisionCard, DecisionKind, Profile};
use fa_time::DateDay;
use fgdb_delta_types::PropertyKeyId;
use fgdb_types::{CanonicalScalar, CommitSeq, VId};

use super::{BankMatchRecorded, BankMatchRequest, bank_match_vid, invalid};
use crate::evidence::document_vid;
use crate::genesis::BookContext;
use crate::refusal::{KernelError, Outcome};
use crate::rows::{scalar_bytes, scalar_text};

pub(super) const LINE_DOMAIN: &[u8] = b"fa:bank-line-doc:v1";
const PROPOSAL_DOMAIN: &[u8] = b"fa:reconciliation-match:v1";
const MATCH_DOMAIN: &[u8] = b"fa:bank-match-confirmation:v1";
const MATCH_MAGIC: &[u8; 13] = b"FA-BANK-MATCH";
pub(super) const METHOD: &str = "pinned-exact-one-to-one";
/// A unique proposal has one candidate and exactly three numeric features.
/// The native replay below additionally checks their complete actual values.
const MAX_CONFIRMED_CARD_BYTES: usize = 1024;

/// The retained approval binds a particular historical proposal and its actual
/// cash leg. `proposer` names only the principal inside those proposal bytes;
/// `confirmed_by` is the current authenticated holder who published this fact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BankMatchConfirmation {
    pub book_id: Id128,
    pub manifest_oid: Oid,
    pub manifest_commit: [u8; 32],
    pub statement_oid: Oid,
    pub statement_commit: [u8; 32],
    pub import_run: VId,
    pub import_receipt_hash: [u8; 32],
    pub import_recorded_at: CommitSeq,
    pub account: VId,
    pub line_document_oid: Oid,
    /// The canonical line digest used by Teller, distinct from its Docket OID.
    pub bank_line_oid: Oid,
    pub line_ordinal: u32,
    pub entry_ref: EntryRef,
    pub leg_ordinal: u16,
    pub source_known_at: CommitSeq,
    pub date_window_days: u32,
    pub candidate_ordinal: u64,
    pub proposer: VId,
    pub proposal_digest: [u8; 32],
    pub decision_card: DecisionCard,
    pub confirmed_by: VId,
    pub confirming_profile: Profile,
    pub capability_commitment: [u8; 32],
    pub security_policy_epoch: u64,
}

impl BankMatchConfirmation {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let card = self
            .decision_card
            .canonical_bytes()
            .map_err(|e| KernelError::Model(e.into()))?;
        let mut w = Writer::new();
        w.fixed(MATCH_MAGIC)
            .u16(1)
            .u16(0)
            .fixed(&self.book_id.0)
            .fixed(&self.manifest_oid.0)
            .fixed(&self.manifest_commit)
            .fixed(&self.statement_oid.0)
            .fixed(&self.statement_commit)
            .u128(self.import_run.0)
            .fixed(&self.import_receipt_hash)
            .u64(self.import_recorded_at.0)
            .u128(self.account.0)
            .fixed(&self.line_document_oid.0)
            .fixed(&self.bank_line_oid.0)
            .u32(self.line_ordinal)
            .u128(self.entry_ref.vid.0)
            .fixed(&self.entry_ref.entry_digest)
            .u16(self.leg_ordinal)
            .u64(self.source_known_at.0)
            .u32(self.date_window_days)
            .u64(self.candidate_ordinal)
            .u128(self.proposer.0)
            .fixed(&self.proposal_digest)
            .bytes(&card)
            .u128(self.confirmed_by.0)
            .u8(self.confirming_profile.tag())
            .fixed(&self.capability_commitment)
            .u64(self.security_policy_epoch);
        w.finish().map_err(|e| KernelError::Model(e.into()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(bytes);
        let decoded = (|| -> Result<Self, DecodeError> {
            if r.fixed::<13>("bank_match.magic")? != *MATCH_MAGIC
                || r.u16("bank_match.major")? != 1
                || r.u16("bank_match.minor")? != 0
            {
                return Err(r.invalid("bank_match.version"));
            }
            let result = Self {
                book_id: Id128(r.fixed("bank_match.book_id")?),
                manifest_oid: Oid(r.fixed("bank_match.manifest_oid")?),
                manifest_commit: r.fixed("bank_match.manifest_commit")?,
                statement_oid: Oid(r.fixed("bank_match.statement_oid")?),
                statement_commit: r.fixed("bank_match.statement_commit")?,
                import_run: VId(r.u128("bank_match.import_run")?),
                import_receipt_hash: r.fixed("bank_match.import_receipt_hash")?,
                import_recorded_at: CommitSeq(r.u64("bank_match.import_recorded_at")?),
                account: VId(r.u128("bank_match.account")?),
                line_document_oid: Oid(r.fixed("bank_match.line_document_oid")?),
                bank_line_oid: Oid(r.fixed("bank_match.bank_line_oid")?),
                line_ordinal: r.u32("bank_match.line_ordinal")?,
                entry_ref: EntryRef {
                    vid: VId(r.u128("bank_match.entry")?),
                    entry_digest: r.fixed("bank_match.entry_digest")?,
                },
                leg_ordinal: r.u16("bank_match.leg_ordinal")?,
                source_known_at: CommitSeq(r.u64("bank_match.source_known_at")?),
                date_window_days: r.u32("bank_match.date_window_days")?,
                candidate_ordinal: r.u64("bank_match.candidate_ordinal")?,
                proposer: VId(r.u128("bank_match.proposer")?),
                proposal_digest: r.fixed("bank_match.proposal_digest")?,
                decision_card: DecisionCard::decode(r.bytes(
                    fa_model::limits::MAX_ENTRY_BYTES,
                    "bank_match.decision_card",
                )?)?,
                confirmed_by: VId(r.u128("bank_match.confirmed_by")?),
                confirming_profile: Profile::from_tag(r.u8("bank_match.confirming_profile")?)
                    .ok_or_else(|| r.invalid("bank_match.confirming_profile"))?,
                capability_commitment: r.fixed("bank_match.capability_commitment")?,
                security_policy_epoch: r.u64("bank_match.security_policy_epoch")?,
            };
            if result.import_recorded_at.0 == 0
                || result.line_ordinal == 0
                || result.import_recorded_at > result.source_known_at
                || result.date_window_days > i32::MAX as u32
            {
                return Err(r.invalid("bank_match.source_coordinates"));
            }
            if result.confirming_profile != Profile::Human {
                return Err(r.invalid("bank_match.confirming_profile"));
            }
            r.finish()?;
            Ok(result)
        })()
        .map_err(|error| KernelError::Model(error.into()))?;
        if decoded.canonical_bytes()? != bytes {
            return Err(KernelError::Corrupt(
                "bank match has noncanonical bytes".into(),
            ));
        }
        Ok(decoded)
    }

    pub fn digest(&self) -> Result<[u8; 32], KernelError> {
        Ok(domain_digest(MATCH_DOMAIN, &[&self.canonical_bytes()?]))
    }

    #[must_use]
    pub fn vid(&self) -> VId {
        bank_match_vid(self.book_id, self.statement_oid, self.line_ordinal)
    }

    pub(super) fn from_request(
        book: &BookContext,
        cap: &Capability,
        security_policy_epoch: u64,
        request: BankMatchRequest,
        line: BankLine,
    ) -> Result<Self, KernelError> {
        let manifest = request.import.manifest();
        let binding = request.import.predecessor();
        let capability_commitment = cap
            .commitment()
            .map_err(|e| KernelError::Corrupt(e.to_string()))?;
        Ok(Self {
            book_id: book.book_id,
            manifest_oid: request.import.manifest_oid(),
            manifest_commit: binding.manifest_commit,
            statement_oid: manifest.statement_oid,
            statement_commit: manifest.statement_commit,
            import_run: request.import.receipt().run,
            import_receipt_hash: request.import.receipt().receipt_hash,
            import_recorded_at: request.import.receipt().recorded_at,
            account: manifest.account,
            line_document_oid: request.line.oid(),
            bank_line_oid: line.oid,
            line_ordinal: line.line_ordinal,
            entry_ref: request.entry_ref,
            leg_ordinal: request.leg_ordinal,
            source_known_at: request.source_known_at,
            date_window_days: request.date_window_days,
            candidate_ordinal: request.candidate_ordinal,
            proposer: request.proposer,
            proposal_digest: request.proposal_digest,
            decision_card: request.decision_card,
            confirmed_by: cap.holder(),
            confirming_profile: cap.profile(),
            capability_commitment,
            security_policy_epoch,
        })
    }

    pub(super) fn same_request(&self, request: &BankMatchRequest, line: &BankLine) -> bool {
        self.manifest_oid == request.import.manifest_oid()
            && self.manifest_commit == request.import.predecessor().manifest_commit
            && self.statement_oid == request.import.manifest().statement_oid
            && self.statement_commit == request.import.manifest().statement_commit
            && self.import_run == request.import.receipt().run
            && self.import_receipt_hash == request.import.receipt().receipt_hash
            && self.import_recorded_at == request.import.receipt().recorded_at
            && self.account == request.import.manifest().account
            && self.line_document_oid == request.line.oid()
            && self.bank_line_oid == line.oid
            && self.line_ordinal == line.line_ordinal
            && self.entry_ref == request.entry_ref
            && self.leg_ordinal == request.leg_ordinal
            && self.source_known_at == request.source_known_at
            && self.date_window_days == request.date_window_days
            && self.candidate_ordinal == request.candidate_ordinal
            && self.proposer == request.proposer
            && self.proposal_digest == request.proposal_digest
            && self.decision_card == request.decision_card
    }

    pub(super) fn recorded(
        &self,
        recorded_at: CommitSeq,
        already_recorded: bool,
    ) -> Result<BankMatchRecorded, KernelError> {
        Ok(BankMatchRecorded {
            match_vid: self.vid(),
            match_digest: self.digest()?,
            recorded_at,
            already_recorded,
            confirmation: self.clone(),
        })
    }

    pub(super) fn source_vertices(&self) -> Vec<VId> {
        let mut sources = vec![
            document_vid(&self.manifest_oid),
            document_vid(&self.statement_oid),
            document_vid(&self.line_document_oid),
            self.import_run,
            self.entry_ref.vid,
        ];
        sources.sort();
        sources.dedup();
        sources
    }
}

/// The bounded bank-line document wire already published by Teller. Private
/// source strings are used only for exact eligibility; they are not copied
/// into a public confirmation record or edge.
pub(super) struct BankLine {
    pub oid: Oid,
    pub statement_oid: Oid,
    pub statement_seq: u64,
    pub line_ordinal: u32,
    pub booking_date: DateDay,
    pub side: Side,
    pub amount: Amount,
    pub reference: String,
}

impl BankLine {
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(bytes);
        if r.bytes(64, "bank_line.domain")? != LINE_DOMAIN {
            return Err(r.invalid("bank_line.domain"));
        }
        let statement_oid = Oid(r.fixed("bank_line.statement_oid")?);
        let statement_seq = r.u64("bank_line.statement_seq")?;
        let line_ordinal = r.u32("bank_line.line_ordinal")?;
        let booking_date = DateDay(r.i32("bank_line.booking_date")?);
        r.i32("bank_line.value_date")?;
        let side = match r.u8("bank_line.side")? {
            0 => Side::Debit,
            1 => Side::Credit,
            _ => return Err(r.invalid("bank_line.side")),
        };
        let unit = UnitId(r.u32("bank_line.unit")?);
        let mantissa = r.i128("bank_line.mantissa")?;
        if mantissa <= 0 {
            return Err(r.invalid("bank_line.mantissa"));
        }
        r.str(fa_model::limits::MAX_MEMO_BYTES, "bank_line.counterparty")?;
        let reference = r
            .str(fa_model::limits::MAX_MEMO_BYTES, "bank_line.reference")?
            .to_string();
        r.finish()?;
        Ok(Self {
            oid: Oid(domain_digest(LINE_DOMAIN, &[bytes])),
            statement_oid,
            statement_seq,
            line_ordinal,
            booking_date,
            side,
            amount: Amount::new(unit, mantissa),
            reference,
        })
    }
}

/// Exact v1 `ReconciliationMatch` wire for the supported one-to-one shape.
/// Keeping the already published digest lets a reviewer approve the value
/// printed by `bank match`, without changing that report's canonical bytes.
pub(super) fn proposal_digest(
    line: Oid,
    entry: EntryRef,
    candidate: u64,
    proposer: VId,
    card: &DecisionCard,
) -> Result<[u8; 32], KernelError> {
    let bytes = card
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
    let mut w = Writer::new();
    w.bytes(PROPOSAL_DOMAIN)
        .list(&[line], |w, oid| {
            w.fixed(&oid.0);
        })
        .list(&[entry], |w, entry| {
            w.u128(entry.vid.0).fixed(&entry.entry_digest);
        })
        .opt(Some(&candidate), |w, ordinal| {
            w.u64(*ordinal);
        })
        .u8(0)
        .bytes(&bytes)
        .u128(proposer.0)
        .u8(0);
    let bytes = w.finish().map_err(|e| KernelError::Model(e.into()))?;
    Ok(domain_digest(PROPOSAL_DOMAIN, &[&bytes]))
}

pub(super) fn validate_proposal(request: &BankMatchRequest, line: &BankLine) -> Outcome<()> {
    if let Err(error) = validate_card(&request.decision_card, line.oid) {
        return Ok(Err(invalid(error.to_string())));
    }
    if proposal_digest(
        line.oid,
        request.entry_ref,
        request.candidate_ordinal,
        request.proposer,
        &request.decision_card,
    )? != request.proposal_digest
    {
        return Ok(Err(invalid(
            "the selected proposal digest does not bind this exact bank line, Entry and candidate",
        )));
    }
    Ok(Ok(()))
}

pub(super) fn validate_card(card: &DecisionCard, line: Oid) -> Result<(), KernelError> {
    let bytes = card
        .canonical_bytes()
        .map_err(|e| KernelError::Model(e.into()))?;
    let recognized_features = card.features.iter().all(|feature| {
        let Some(tail) = feature.name.strip_prefix("cand.") else {
            return false;
        };
        let Some((ordinal, name)) = tail.split_once('.') else {
            return false;
        };
        !feature.advisory
            && ordinal
                .parse::<u64>()
                .is_ok_and(|value| value.to_string() == ordinal)
            && match name {
                "date_delta_days" => feature.value >= 0 && feature.value <= i128::from(u32::MAX),
                "ref_exact" | "cp_exact" => matches!(feature.value, 0 | 1),
                _ => false,
            }
    });
    if bytes.len() > MAX_CONFIRMED_CARD_BYTES
        || DecisionCard::decode(&bytes).ok().as_ref() != Some(card)
        || card.decision_kind != DecisionKind::BankMatchHeuristic
        || card.policy_epoch.is_some()
        || !card.used_fallback()
        || card.state.as_slice() != line.0.as_slice()
        || card.verify_replay([0; 32]).is_err()
        || !recognized_features
        || card.candidates.iter().any(|candidate| {
            candidate.action != "match_entry_ordinal" || u64::try_from(candidate.parameter).is_err()
        })
    {
        return Err(KernelError::Corrupt("bank confirmation requires a complete canonical pinned bank DecisionCard with only registered numeric features".into()));
    }
    Ok(())
}

pub(super) fn match_props(
    value: &BankMatchConfirmation,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_PAYLOAD,
            scalar_bytes("_fa_payload", value.canonical_bytes()?)?,
        ),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", value.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", value.book_id.0.to_vec())?,
        ),
        (property::CODE, scalar_text("code", METHOD)?),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

pub(super) fn claim_props(
    value: &BankMatchConfirmation,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut w = Writer::new();
    w.u16(1)
        .fixed(&value.book_id.0)
        .u128(value.vid().0)
        .fixed(&value.digest()?)
        .u128(value.entry_ref.vid.0)
        .fixed(&value.entry_ref.entry_digest)
        .u16(value.leg_ordinal);
    let bytes = w.finish().map_err(|e| KernelError::Model(e.into()))?;
    let mut props = vec![
        (property::FA_PAYLOAD, scalar_bytes("_fa_payload", bytes)?),
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", value.digest()?.to_vec())?,
        ),
        (
            property::BOOK_ID,
            scalar_bytes("book_id", value.book_id.0.to_vec())?,
        ),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}

pub(super) fn match_edge_props(
    value: &BankMatchConfirmation,
) -> Result<Vec<(PropertyKeyId, CanonicalScalar)>, KernelError> {
    let mut props = vec![
        (
            property::FA_DIGEST,
            scalar_bytes("_fa_digest", value.digest()?.to_vec())?,
        ),
        (property::CODE, scalar_text("code", METHOD)?),
    ];
    props.sort_by_key(|(key, _)| key.0);
    Ok(props)
}
