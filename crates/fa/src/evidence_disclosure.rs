//! Journal-authenticated, capability-gated evidence disclosure (plan §9/§13).
//!
//! Compose the existing inclusion and protected document producers. The exact
//! entry digest, document identity, citation role and chunk request are caller
//! inputs, never inferred from an untrusted proof. No artifact leaves this
//! operation unless both producers and their binding checks succeed. These are
//! two existing wire formats, not a new bundle, signature or completeness claim.

use asupersync::fs::Vfs;
use fa_journal::{KernelError, Refusal, exit};
use fa_model::{Entry, EvidenceRef, Id128};
use fa_notary::disclosure;
use fa_policy::{Capability, Op};
use fgdb_types::CommitSeq;
use fgdb_types::context::PurposeContexts;

use crate::{
    AsyncBook, Book, BookError, DocumentDisclosureArtifact, Outcome, ProofArtifact, ProofKind,
    ProofRequest,
};

pub use fa_docket::EvidenceDisclosureRequest;

fn proof_request(req: EvidenceDisclosureRequest) -> ProofRequest {
    ProofRequest {
        state: req.state,
        kind: ProofKind::Inclusion {
            entry: req.entry,
            with_record: true,
        },
    }
}

/// Raw entry-inclusion and document-disclosure artifacts for the independent
/// verifier's journal-authenticated document mode. The selected unsigned
/// checkpoint still needs independently established recipient trust.
///
/// The inclusion record reveals the entry's complete committed wire, including
/// its other public evidence citations. This requires whole-book read/produce,
/// not merely permission to read the selected document. The document claim is
/// membership_only; no custody, provenance, authorization or completeness claim
/// is authenticated by these proofs. Debug deliberately omits both wire payloads.
#[derive(Clone, PartialEq, Eq)]
pub struct EvidenceDisclosureArtifact {
    pub entry_digest: [u8; 32],
    pub citation: EvidenceRef,
    pub inclusion: ProofArtifact,
    pub disclosure: DocumentDisclosureArtifact,
}

impl core::fmt::Debug for EvidenceDisclosureArtifact {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EvidenceDisclosureArtifact")
            .field("document", &self.citation.document_oid)
            .field("role", &self.citation.role)
            .field("state", &self.inclusion.checkpoint.oid)
            .field("requested_chunks", &self.disclosure.requested_chunks)
            .field("inclusion_byte_length", &self.inclusion.bytes.len())
            .field("disclosure_byte_length", &self.disclosure.bytes.len())
            .finish_non_exhaustive()
    }
}

fn invalid_request(message: impl Into<String>) -> Refusal {
    Refusal::new(
        fa_journal::refusal::code::STRUCTURE,
        exit::USAGE,
        message,
        "plan §9.1 / §13.1 (exact journal-authenticated evidence selection)",
        "select the expected entry digest and its exact document/role citation, with a nonempty ascending chunk request",
    )
}

fn preflight(book: Id128, capability: &Capability, chunks: &[u64]) -> Result<(), Refusal> {
    // Authority before request inspection or any storage observation. Expiry
    // and revocation are then checked by each existing protected producer.
    fa_policy::admit_read(capability, capability.holder(), book)
        .and_then(|()| fa_policy::require(capability, Op::Produce, "exporting cited evidence"))
        .map_err(|denial| fa_journal::policy::refusal(&denial))?;
    disclosure::validate_request(chunks).map_err(|error| invalid_request(error.to_string()))
}

fn select_citation(
    book: Id128,
    request: EvidenceDisclosureRequest,
    record: Option<(Entry, CommitSeq)>,
    inclusion: &ProofArtifact,
) -> Outcome<EvidenceRef> {
    // The inclusion producer has already admitted this exact entry at the
    // selected checkpoint. Absence or another coordinate is stored corruption,
    // not an invitation to substitute a later entry or another checkpoint.
    let (entry, recorded_at) = record.ok_or_else(|| {
        KernelError::Corrupt("included evidence entry disappeared during export".into())
    })?;
    if entry.proposal.book_id != book || recorded_at > inclusion.checkpoint.state.through_seq {
        return Err(KernelError::Corrupt(
            "evidence entry is outside the selected book/checkpoint".into(),
        )
        .into());
    }
    if entry.entry_digest != request.expected_entry_digest {
        return Ok(Err(invalid_request(
            "the selected entry does not match the expected entry digest",
        )));
    }
    let mut matches = entry.proposal.evidence.iter().filter(|citation| {
        citation.document_oid == request.document && citation.role == request.role
    });
    let Some(citation) = matches.next() else {
        return Ok(Err(invalid_request(
            "the selected entry does not cite this document in the requested role",
        )));
    };
    if matches.next().is_some()
        || fa_journal::evidence::document_oid(book, &citation.doc_commit) != request.document
    {
        return Err(KernelError::Corrupt(
            "evidence citation is duplicated or bound to another book/document".into(),
        )
        .into());
    }
    Ok(Ok(*citation))
}

fn finish(
    request: EvidenceDisclosureRequest,
    citation: EvidenceRef,
    inclusion: ProofArtifact,
    disclosure: DocumentDisclosureArtifact,
) -> Outcome<EvidenceDisclosureArtifact> {
    if disclosure.document != citation.document_oid || disclosure.doc_commit != citation.doc_commit
    {
        return Err(KernelError::Corrupt(
            "protected disclosure does not match the entry's exact document commitment".into(),
        )
        .into());
    }
    Ok(Ok(EvidenceDisclosureArtifact {
        entry_digest: request.expected_entry_digest,
        citation,
        inclusion,
        disclosure,
    }))
}

impl Book {
    /// Produce an entry proof (including its committed record) and exactly the
    /// requested permitted document chunks, bound to the selected citation.
    /// Current read/produce authority is mandatory. Governed evidence continues
    /// to require an existing readable view unless privileged is independently
    /// held; this method never derives a view or upgrades the caller's authority.
    /// Every outcome leaves journal, custody and checkpoint state unchanged.
    pub fn export_evidence_disclosure(
        &mut self,
        capability: &Capability,
        request: EvidenceDisclosureRequest,
        requested_chunks: &[u64],
    ) -> Outcome<EvidenceDisclosureArtifact> {
        let book = self.context().book_id;
        if let Err(refusal) = preflight(book, capability, requested_chunks) {
            return Ok(Err(refusal));
        }
        let inclusion =
            match self.export_proof(capability.holder(), capability, proof_request(request))? {
                Ok(proof) => proof,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let citation =
            match select_citation(book, request, self.read_entry(request.entry)?, &inclusion)? {
                Ok(citation) => citation,
                Err(refusal) => return Ok(Err(refusal)),
            };
        let disclosed = match self.export_document_disclosure(
            capability,
            &request.document,
            requested_chunks,
        )? {
            Ok(disclosed) => disclosed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        finish(request, citation, inclusion, disclosed)
    }
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    /// The same operation on the caller's runtime and filesystem. No runtime,
    /// detached task, publication or fresh clock observation is introduced.
    /// Cancellation discards the whole result, including any already prepared
    /// inclusion artifact; neither producer performs a book write.
    pub async fn export_evidence_disclosure(
        &mut self,
        cx: &PurposeContexts,
        capability: &Capability,
        request: EvidenceDisclosureRequest,
        requested_chunks: &[u64],
    ) -> Outcome<EvidenceDisclosureArtifact> {
        let book = self.context().book_id;
        if let Err(refusal) = preflight(book, capability, requested_chunks) {
            return Ok(Err(refusal));
        }
        let query = cx.query();
        query.checkpoint().map_err(BookError::Context)?;
        let inclusion =
            match self.export_proof(cx, capability.holder(), capability, proof_request(request))? {
                Ok(proof) => proof,
                Err(refusal) => return Ok(Err(refusal)),
            };
        query.checkpoint().map_err(BookError::Context)?;
        let citation = match select_citation(
            book,
            request,
            self.read_entry(cx, request.entry)?,
            &inclusion,
        )? {
            Ok(citation) => citation,
            Err(refusal) => return Ok(Err(refusal)),
        };
        query.checkpoint().map_err(BookError::Context)?;
        let disclosed = match self
            .export_document_disclosure(cx, capability, &request.document, requested_chunks)
            .await?
        {
            Ok(disclosed) => disclosed,
            Err(refusal) => return Ok(Err(refusal)),
        };
        let artifact = finish(request, citation, inclusion, disclosed);
        query.checkpoint().map_err(BookError::Context)?;
        artifact
    }
}
