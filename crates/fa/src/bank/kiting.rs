//! Source-authenticated inputs for temporal bank-instrument screening.
//!
//! Only native active matches on both original cash legs of an exact transfer
//! can contribute. Instrument identities and dates are reread from the retained
//! statement parse; neither journal descriptions nor caller-supplied pairs are
//! accepted as bank evidence.

use super::*;
use fa_journal::bank::{self as native, BankMatchRecorded};
use fa_lantern::Snapshot;
use fa_lantern::kiting::{BankTransfer, MAX_KITING_TRANSFERS, MatchedBankLine};
use fa_model::Id128;

/// This value cannot be constructed outside this source-verification module.
/// Its selected prefix is pinned before any original document is fetched.
pub(crate) struct PreparedBankTransfers {
    book_id: Id128,
    known_at: CommitSeq,
    transfers: Vec<BankTransfer>,
}

impl PreparedBankTransfers {
    pub(crate) fn known_at(&self) -> CommitSeq {
        self.known_at
    }

    pub(crate) fn same_sources(&self, other: &Self) -> bool {
        self.book_id == other.book_id && self.transfers == other.transfers
    }

    pub(crate) fn populate(&self, snapshot: &mut Snapshot) -> Result<(), Refusal> {
        if snapshot.coordinate.book_id != self.book_id
            || snapshot.coordinate.known_at != self.known_at
        {
            return Err(closure_drift(
                "verified bank transfers belong to a different snapshot",
            ));
        }
        snapshot.bank_transfers = Some(self.transfers.clone());
        Ok(())
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    pub(crate) async fn prepare_kiting_inputs(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        known_at: Option<CommitSeq>,
    ) -> Outcome<PreparedBankTransfers> {
        let context = self.context().clone();
        // Full-source native matching has a stronger contract than the public
        // metadata inventory. Admit it before history, journal or blob reads.
        if let Err(refusal) = native::admit_bank_match(&self.db, &context, capability)? {
            return Ok(Err(refusal));
        }
        let history = match native::bank_match_history(
            &mut self.db,
            cx,
            &context,
            capability,
            known_at,
            None,
        )
        .await?
        {
            Ok(history) => history,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let at = history.known_at;
        let snapshot = self.query(cx, |db, book| {
            Ok(Snapshot::read(db, &cx.query(), book, Some(at), None)?)
        })?;
        let mut active = BTreeMap::new();
        for recorded in history.active {
            let key = (
                recorded.confirmation.entry_ref.vid,
                recorded.confirmation.leg_ordinal,
            );
            if active.insert(key, recorded).is_some() {
                return Ok(Err(closure_drift(
                    "more than one active bank confirmation occupies a cash leg",
                )));
            }
        }
        let mut imports = BTreeMap::new();
        let mut transfers = Vec::new();
        for entry in &snapshot.entries {
            cx.query().checkpoint().map_err(BookError::Context)?;
            let legs = &entry.entry.proposal.legs;
            if !entry.posts()
                || legs.len() != 2
                || legs
                    .iter()
                    .any(|leg| !snapshot.roles.holds(leg.account_ref, "cash"))
                || legs[0].account_ref == legs[1].account_ref
                || legs[0].side == legs[1].side
                || legs[0].amount != legs[1].amount
                || legs[0].amount.mantissa <= 0
            {
                continue;
            }
            let source_ordinal = u16::from(legs[0].side != Side::Credit);
            let destination_ordinal = 1 - source_ordinal;
            let Some(source) = active.get(&(entry.vid, source_ordinal)) else {
                continue;
            };
            let Some(destination) = active.get(&(entry.vid, destination_ordinal)) else {
                continue;
            };
            let entry_ref = entry.entry.entry_ref(entry.vid);
            if source.confirmation.entry_ref != entry_ref
                || destination.confirmation.entry_ref != entry_ref
            {
                return Ok(Err(closure_drift(
                    "an active transfer confirmation differs from its original Entry",
                )));
            }
            if transfers.len() == MAX_KITING_TRANSFERS {
                return Ok(Err(Refusal::new(
                    code::DOCUMENT_INTAKE,
                    exit::REFUSAL,
                    "graph.kiting exceeds its paired-transfer population bound",
                    "plan §11.1 (bounded deterministic procedures)",
                    "select an earlier known-at prefix; no partial cycle inventory was returned",
                )));
            }
            let source = match self
                .verified_kiting_line(cx, capability, source, at, &mut imports)
                .await?
            {
                Ok(line) => line,
                Err(refusal) => return Ok(Err(refusal)),
            };
            let destination = match self
                .verified_kiting_line(cx, capability, destination, at, &mut imports)
                .await?
            {
                Ok(line) => line,
                Err(refusal) => return Ok(Err(refusal)),
            };
            transfers.push(BankTransfer {
                entry: entry_ref,
                source_ordinal,
                destination_ordinal,
                source,
                destination,
            });
        }
        transfers.sort_by_key(|transfer| (transfer.entry, transfer.source_ordinal));
        if let Err(refusal) = native::admit_bank_match(&self.db, &context, capability)? {
            return Ok(Err(refusal));
        }
        Ok(Ok(PreparedBankTransfers {
            book_id: context.book_id,
            known_at: at,
            transfers,
        }))
    }

    async fn verified_kiting_line(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        claim: &BankMatchRecorded,
        at: CommitSeq,
        imports: &mut BTreeMap<Oid, VerifiedBankImport>,
    ) -> Outcome<MatchedBankLine> {
        let confirmation = &claim.confirmation;
        if let std::collections::btree_map::Entry::Vacant(slot) =
            imports.entry(confirmation.manifest_oid)
        {
            let verified = match self
                .load_bank_import(cx, capability, confirmation.manifest_oid, at)
                .await?
            {
                Ok(verified) => verified,
                Err(refusal) => return Ok(Err(refusal)),
            };
            if let Err(refusal) = self
                .verify_bank_predecessors(cx, capability, &verified, at)
                .await?
            {
                return Ok(Err(refusal));
            }
            slot.insert(verified);
        }
        let verified = imports
            .get(&confirmation.manifest_oid)
            .ok_or_else(|| corrupt("an active transfer's original bank import was not loaded"))?;
        let context = self.context().clone();
        let original = match native::read_bank_match(
            &mut self.db,
            cx,
            &context,
            capability,
            claim.match_vid,
            Some(at),
            Some(&verified.manifest),
        )
        .await?
        {
            Ok(Some(original)) => original,
            Ok(None) => {
                return Ok(Err(closure_drift(
                    "an active transfer confirmation disappeared during source replay",
                )));
            }
            Err(refusal) => return Ok(Err(refusal)),
        };
        if &original != claim {
            return Ok(Err(closure_drift(
                "an active transfer confirmation changed during source replay",
            )));
        }
        let Some((oid, line)) = verified
            .manifest
            .line_oids
            .iter()
            .zip(&verified.lines)
            .find(|(_, line)| line.line_ordinal == confirmation.line_ordinal)
        else {
            return Ok(Err(closure_drift(
                "a transfer confirmation's bank line is absent from its original parse",
            )));
        };
        if *oid != confirmation.line_document_oid
            || verified.manifest.account != confirmation.account
            || line.statement_oid != confirmation.statement_oid
        {
            return Ok(Err(closure_drift(
                "a transfer confirmation's bank line or account differs from its original parse",
            )));
        }
        Ok(Ok(MatchedBankLine {
            manifest_oid: confirmation.manifest_oid,
            line_oid: *oid,
            account: confirmation.account,
            instrument: verified.extract.instrument_account_id.clone(),
            booking_date: line.booking_date,
            value_date: line.value_date,
        }))
    }
}
