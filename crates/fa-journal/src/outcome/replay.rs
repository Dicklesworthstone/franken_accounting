//! Private lineage for a verified accounting replay of recovered coverage.
//! Source coverage and claims remain byte-identical. Native markers change
//! when maintenance is omitted; a separately authenticated witness binds the
//! copied coverage to the actual scratch prefix before its publication.

use fa_model::SealKey;
use fa_model::symbols::relation;

use super::*;

const MAGIC: &[u8; 18] = b"FA-OUTCOME-REPLAY\0";

pub(crate) fn replay_vid(book: Id128) -> VId {
    let digest = domain_digest(b"fa:vid:intent-outcome-replay:v1", &[&book.0]);
    let mut low = [0; 16];
    low.copy_from_slice(&digest[..16]);
    VId(u128::from_le_bytes(low))
}

pub(crate) fn recovered_coverage_bytes(value: &CanonicalScalar) -> bool {
    matches!(value, CanonicalScalar::Bytes(encoded)
        if encoded.as_slice().starts_with(COVERAGE_MAGIC)
            && Coverage::decode(encoded.as_slice()).is_ok_and(|coverage| coverage.basis != CommitSeq(0)))
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ReplayWitness {
    book: Id128,
    coverage_digest: [u8; 32],
    source_marker: [u8; 32],
    basis: CommitSeq,
    scratch_marker: [u8; 32],
    authentication: [u8; 32],
}

impl ReplayWitness {
    fn authentication_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut w = Writer::new();
        w.fixed(MAGIC)
            .u16(VERSION)
            .u16(0)
            .fixed(&self.book.0)
            .fixed(&self.coverage_digest)
            .fixed(&self.source_marker)
            .u64(self.basis.0)
            .fixed(&self.scratch_marker);
        Ok(w.finish()?)
    }

    fn canonical_bytes(&self) -> Result<Vec<u8>, KernelError> {
        let mut bytes = self.authentication_bytes()?;
        bytes.extend_from_slice(&self.authentication);
        Ok(bytes)
    }

    fn authenticate(&self, key: &SealKey) -> Result<[u8; 32], KernelError> {
        let key = fgdb_crypto::derive_key("fa:outcome-replay-authentication:v1", &key.0);
        Ok(fgdb_crypto::keyed_hash(&key, &self.authentication_bytes()?).0)
    }

    fn decode(encoded: &[u8]) -> Result<Self, KernelError> {
        let mut r = Reader::new(encoded);
        if r.fixed::<18>("coverage replay magic").map_err(decode)? != *MAGIC
            || r.u16("coverage replay major").map_err(decode)? != VERSION
            || r.u16("coverage replay minor").map_err(decode)? != 0
        {
            return Err(KernelError::Corrupt(
                "unsupported coverage replay witness".into(),
            ));
        }
        let value = Self {
            book: Id128(r.fixed("coverage replay book").map_err(decode)?),
            coverage_digest: r.fixed("coverage replay digest").map_err(decode)?,
            source_marker: r.fixed("coverage replay source").map_err(decode)?,
            basis: CommitSeq(r.u64("coverage replay basis").map_err(decode)?),
            scratch_marker: r.fixed("coverage replay scratch").map_err(decode)?,
            authentication: r.fixed("coverage replay authentication").map_err(decode)?,
        };
        r.finish().map_err(decode)?;
        Ok(value)
    }
}

fn coverage_digest(coverage: &Coverage) -> Result<[u8; 32], KernelError> {
    Ok(domain_digest(
        b"fa:outcome-coverage:v1",
        &[&coverage.canonical_bytes()?],
    ))
}

/// Fields are private: only authenticating the original source coverage can
/// authorize a copier to mint a witness for its new native prefix.
#[derive(Debug)]
pub(crate) struct VerifiedCoverageReplay {
    coverage: Coverage,
    seal_key: SealKey,
}

pub(crate) fn prepare_replay<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    prefix: CommitSeq,
) -> Result<Option<VerifiedCoverageReplay>, KernelError> {
    let Some(row) = db.vertex_at(coverage_vid(book.book_id), prefix)? else {
        return Ok(None);
    };
    let coverage = coverage_of(db, book, &row)?;
    Ok(
        (coverage.basis != CommitSeq(0)).then(|| VerifiedCoverageReplay {
            coverage,
            seal_key: book.seal_key.clone(),
        }),
    )
}

impl VerifiedCoverageReplay {
    pub(crate) fn publication(&self) -> CommitSeq {
        CommitSeq(self.coverage.basis.0 + 1)
    }

    /// Called only by the native replay loop at the corresponding copied
    /// publication. The witness is staged with, never after, the coverage.
    pub(crate) fn stage<V: Vfs + Clone>(
        &self,
        target: &Database<V>,
    ) -> Result<WriteBatch, KernelError> {
        if target.frontier()? != self.coverage.basis {
            return Err(KernelError::Corrupt(
                "coverage replay did not preserve its source coordinates".into(),
            ));
        }
        let mut witness = ReplayWitness {
            book: self.coverage.book,
            coverage_digest: coverage_digest(&self.coverage)?,
            source_marker: self.coverage.source_marker,
            basis: self.coverage.basis,
            scratch_marker: marker_at(target, self.coverage.basis)?,
            authentication: [0; 32],
        };
        witness.authentication = witness.authenticate(&self.seal_key)?;
        let mut stage = WriteBatch::new(relation::IN_BOOK);
        stage.create_vertex(
            replay_vid(witness.book),
            vec![label::INTENT_OUTCOME],
            vec![
                (
                    property::FA_PAYLOAD,
                    scalar_bytes("coverage replay witness", witness.canonical_bytes()?)?,
                ),
                (
                    property::BOOK_ID,
                    scalar_bytes("coverage replay book", witness.book.0.to_vec())?,
                ),
            ],
        );
        Ok(stage)
    }
}

pub(super) fn verify_replay<V: Vfs + Clone>(
    db: &Database<V>,
    book: &BookContext,
    coverage_row: &VertexRow,
    coverage: &Coverage,
) -> Result<bool, KernelError> {
    let Some(row) = db.vertex(replay_vid(book.book_id))? else {
        return Ok(false);
    };
    if row.labels.as_slice() != [label::INTENT_OUTCOME]
        || row.props.len() != 2
        || row.created_at != coverage_row.created_at
        || !original(db, &row)?
        || !matches!(prop(&row, property::BOOK_ID), Some(CanonicalScalar::Bytes(value)) if value.as_slice() == book.book_id.0)
    {
        return Ok(false);
    }
    let witness = ReplayWitness::decode(&bytes(
        &row,
        property::FA_PAYLOAD,
        "coverage replay witness",
    )?)?;
    Ok(witness.book == book.book_id
        && witness.basis == coverage.basis
        && witness.source_marker == coverage.source_marker
        && witness.coverage_digest == coverage_digest(coverage)?
        && witness.scratch_marker == marker_at(db, coverage.basis)?
        && witness.authentication == witness.authenticate(&book.seal_key)?)
}
