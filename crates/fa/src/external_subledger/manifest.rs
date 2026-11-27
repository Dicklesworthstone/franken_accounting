//! Verify a reviewed source declaration against the journal at a fixed prefix.

use super::{invalid, reconciliation};
use crate::{AsyncBook, BookError, Outcome};
use asupersync::fs::Vfs;
use fa_journal::attestation::Review;
use fa_journal::external_subledger::manifest::{
    EXTERNAL_FEED_MANIFEST_MIME, ExternalFeedManifestVerification, MAX_EXTERNAL_MANIFEST_BYTES,
    MAX_EXTERNAL_MANIFEST_CHILDREN, reviewed_manifest_at,
};
use fa_journal::external_subledger::{
    EXTERNAL_SUBLEDGER_DOCUMENT_KIND, reconcile_unchanged_at, validate_summary,
};
use fa_journal::{DocumentRead, KernelError};
use fa_model::Oid;
use fa_policy::{Capability, Observes, Reach};
use fgdb_types::context::PurposeContexts;
use fgdb_types::{CommitSeq, VId};

/// The reviewed parent document and the complete comparison at the selected prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedFeedManifest {
    pub document: Oid,
    pub review: Review,
    pub known_at: CommitSeq,
    pub comparison: ExternalFeedManifestVerification,
}

impl<V: Vfs + Clone, B: Vfs + Clone> AsyncBook<V, B> {
    pub async fn verify_external_feed_manifest(
        &mut self,
        cx: &PurposeContexts,
        principal: VId,
        capability: &Capability,
        document: Oid,
        known_at: Option<CommitSeq>,
    ) -> Outcome<VerifiedFeedManifest> {
        let at = match reconciliation::authorize(self, cx, principal, capability, known_at, false)? {
            Ok(at) => at,
            Err(r) => return Ok(Err(r)),
        };
        if let Err(r) = self
            .prepare_external_feed_history(cx, principal, capability, Some(at))
            .await?
        {
            return Ok(Err(r));
        }
        let exists = self.query(cx, |db, _| {
            Ok(db.vertex_at(fa_journal::evidence::document_vid(&document), at)
                .map_err(KernelError::from)?.is_some())
        })?;
        if !exists {
            return Ok(Err(invalid("manifest Workpaper is absent at the selected prefix")));
        }
        let reach = Reach {
            branch: Some(fa_model::Id128::TRUNK),
            observes: Observes::At(at),
            periods: None,
            through: None,
            accounts: None,
        };
        let query = cx.query();
        let read = query.with_restriction_async(fa_journal::redaction::read_document_for_with(
            &mut self.db, cx, &self.context, capability, &reach, &self.blobs, document,
            |record| {
                if record.kind != EXTERNAL_SUBLEDGER_DOCUMENT_KIND
                    || record.mime != EXTERNAL_FEED_MANIFEST_MIME
                    || record.size > MAX_EXTERNAL_MANIFEST_BYTES as u64
                {
                    return Err(invalid("a bounded external-feed manifest Workpaper is required"));
                }
                Ok(())
            },
        )).await?;
        // Recheck launch authority after blob I/O, before disclosing its result.
        if let Err(r) = reconciliation::authorize(self, cx, principal, capability, Some(at), false)? {
            return Ok(Err(r));
        }
        let bytes = match read {
            Ok(DocumentRead::Full(doc)) => doc.bytes,
            Ok(DocumentRead::Redacted(_)) => return Ok(Err(invalid("manifest comparison requires the complete Workpaper"))),
            Err(r) => return Ok(Err(r)),
        };
        self.query(cx, |db, book| {
            let (manifest, review) = match reviewed_manifest_at(db, book, document, &bytes, at)? {
                Ok(pair) => pair,
                Err(r) => return Ok(Err(r)),
            };
            let mut batches = Vec::new();
            // Select the journal independently of the parent's declared keys.
            // This also finds deliveries omitted from the source declaration.
            for (vid, entry, _) in fa_registers::entries_at(db, book, at)? {
                cx.query().checkpoint().map_err(BookError::Context)?;
                let day = entry.proposal.effective_date;
                if day < manifest.effective_from || day > manifest.effective_through {
                    continue;
                }
                match validate_summary(&entry.proposal) {
                    Ok(Some(batch)) if batch.feed == manifest.feed => {}
                    Ok(_) => continue,
                    Err(r) => return Ok(Err(r)),
                }
                if batches.len() == MAX_EXTERNAL_MANIFEST_CHILDREN {
                    return Ok(Err(invalid("observed feed exceeds the manifest child bound")));
                }
                match reconcile_unchanged_at(db, book, entry.entry_ref(vid), at)? {
                    Ok(child) => batches.push(child),
                    Err(r) => return Ok(Err(r)),
                }
            }
            Ok(manifest.verify(&batches).map(|comparison| VerifiedFeedManifest {
                document, review, known_at: at, comparison,
            }))
        })
    }
}
