//! Native storage encoding for report artifacts larger than a vertex row.
//!
//! Only the root is a public certificate locator. Parts have distinct,
//! book/digest/ordinal-derived identities. Both use the existing Certificate
//! maintenance label, so scratch replay excludes the entire representation.
//! Manifest and parts are indivisible at publication; no separately durable
//! staging state, custom cache, filesystem access or per-part commits exist.

use super::*;
use fa_model::{Reader, Writer};

/// Leaves room in the pinned substrate's 16 KiB encoded vertex row for the
/// byte-scalar encoding, three mirrors and fragment framing. Also the inline
/// threshold. Export formats keep their existing 64 MiB bound.
pub(super) const CHUNK_BYTES: usize = 12 * 1024;
pub(super) const MANIFEST_FORMAT: &[u8] = b"fa:certificate-chunks:v1";
const FRAGMENT_FORMAT: &[u8] = b"fa:certificate-fragment:v1";
const FRAGMENT_DOMAIN: &[u8] = b"fa:vid:report-certificate-fragment:v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Manifest {
    size: usize,
    count: u32,
}

impl Manifest {
    pub(super) fn new(size: usize) -> Result<Self, Refusal> {
        if !(CHUNK_BYTES + 1..=MAX_CERTIFICATE_BYTES).contains(&size) {
            return Err(invalid("chunked certificate length is outside its registered bounds"));
        }
        let count = u32::try_from(size.div_ceil(CHUNK_BYTES))
            .map_err(|_| invalid("certificate fragment count exceeds u32"))?;
        Ok(Self { size, count })
    }

    pub(super) fn encode(self) -> Result<Vec<u8>, Refusal> {
        let mut w = Writer::new();
        w.fixed(MANIFEST_FORMAT)
            .u64(self.size as u64)
            .u32(CHUNK_BYTES as u32)
            .u32(self.count);
        w.finish().map_err(|error| invalid(format!("certificate manifest: {error}")))
    }

    /// Only a complete matching tag selects the new representation. Other
    /// bytes go through the legacy certificate decoder, which refuses unknown
    /// or truncated formats. Validate size/count BEFORE allocation or lookups.
    pub(super) fn decode(payload: &[u8]) -> Result<Option<Self>, Refusal> {
        if !payload.starts_with(MANIFEST_FORMAT) {
            return Ok(None);
        }
        let mut r = Reader::new(payload);
        let bad = |error| invalid(format!("malformed certificate manifest: {error}"));
        r.fixed::<{ MANIFEST_FORMAT.len() }>("certificate storage format").map_err(bad)?;
        let size = r.u64("certificate byte length").map_err(bad)?;
        let chunk_bytes = r.u32("certificate fragment capacity").map_err(bad)?;
        let count = r.u32("certificate fragment count").map_err(bad)?;
        r.finish().map_err(bad)?;
        let size = usize::try_from(size)
            .map_err(|_| invalid("certificate byte length is not addressable"))?;
        let manifest = Self::new(size)?;
        if chunk_bytes != CHUNK_BYTES as u32 || count != manifest.count {
            return Err(invalid("certificate manifest has a noncanonical fragment size or count"));
        }
        Ok(Some(manifest))
    }

    fn part_len(self, index: u32) -> Result<usize, Refusal> {
        if index >= self.count {
            return Err(invalid("certificate fragment ordinal is out of bounds"));
        }
        let offset = (index as usize).checked_mul(CHUNK_BYTES)
            .ok_or_else(|| invalid("certificate fragment offset overflow"))?;
        self.size.checked_sub(offset)
            .map(|remaining| remaining.min(CHUNK_BYTES))
            .filter(|len| *len > 0)
            .ok_or_else(|| invalid("certificate fragment has no declared bytes"))
    }
}

pub(super) fn fragment_vid(book: Id128, digest: &[u8; 32], index: u32) -> VId {
    let hash = domain_digest(FRAGMENT_DOMAIN, &[&book.0, digest, &index.to_le_bytes()]);
    let mut low = [0_u8; 16];
    low.copy_from_slice(&hash[..16]);
    VId(u128::from_le_bytes(low))
}

fn fragment(index: u32, bytes: &[u8]) -> Result<Vec<u8>, Refusal> {
    if bytes.is_empty() || bytes.len() > CHUNK_BYTES {
        return Err(invalid("certificate fragment length is outside its registered bounds"));
    }
    let mut w = Writer::new();
    w.fixed(FRAGMENT_FORMAT).u32(index).bytes(bytes);
    w.finish().map_err(|error| invalid(format!("certificate fragment: {error}")))
}

fn fragment_bytes(payload: &[u8], index: u32, size: usize) -> Result<&[u8], Refusal> {
    let mut r = Reader::new(payload);
    let bad = |error| invalid(format!("malformed certificate fragment {index}: {error}"));
    let tag = r.fixed::<{ FRAGMENT_FORMAT.len() }>("certificate fragment format").map_err(bad)?;
    if tag.as_slice() != FRAGMENT_FORMAT || r.u32("certificate fragment ordinal").map_err(bad)? != index {
        return Err(invalid(format!("certificate fragment {index} has a different format or ordinal")));
    }
    let bytes = r.bytes(CHUNK_BYTES, "certificate fragment bytes").map_err(bad)?;
    r.finish().map_err(bad)?;
    if bytes.len() != size {
        return Err(invalid(format!("certificate fragment {index} length disagrees with its manifest")));
    }
    Ok(bytes)
}

/// Construct a single batch. The caller performs canonical and native replay
/// verification first, and retains the same root-absence witness until commit.
pub(super) fn stage(
    cx: &QueryCx,
    book: &BookContext,
    digest: &[u8; 32],
    root: VId,
    bytes: Vec<u8>,
) -> Outcome<WriteBatch> {
    cx.checkpoint().map_err(BookError::Context)?;
    let mut batch = WriteBatch::new(relation::DERIVED_FROM);
    if bytes.len() <= CHUNK_BYTES {
        stage_record(&mut batch, book, digest, root, bytes)?;
        return Ok(Ok(batch));
    }
    let manifest = match Manifest::new(bytes.len()) {
        Ok(manifest) => manifest,
        Err(refusal) => return Ok(Err(refusal)),
    };
    let encoded = match manifest.encode() {
        Ok(encoded) => encoded,
        Err(refusal) => return Ok(Err(refusal)),
    };
    stage_record(&mut batch, book, digest, root, encoded)?;
    for (index, bytes) in bytes.chunks(CHUNK_BYTES).enumerate() {
        cx.checkpoint().map_err(BookError::Context)?;
        let index = u32::try_from(index)
            .map_err(|_| KernelError::Corrupt("bounded certificate ordinal exceeds u32".into()))?;
        let payload = match fragment(index, bytes) {
            Ok(payload) => payload,
            Err(refusal) => return Ok(Err(refusal)),
        };
        stage_record(&mut batch, book, digest, fragment_vid(book.book_id, digest, index), payload)?;
    }
    Ok(Ok(batch))
}

/// Resolve parts only at the caller's single pinned snapshot. Exact same-birth
/// admission rejects later repairs and substitutions, including restoration of
/// byte-identical data. The caller validates the reconstructed certificate's
/// full digest and book after this succeeds; pieces are not standalone proofs.
#[allow(clippy::too_many_arguments)]
pub(super) fn read<V: Vfs + Clone>(
    db: &Database<V>,
    cx: &QueryCx,
    book: &BookContext,
    digest: &[u8; 32],
    root: &VertexRow,
    at: CommitSeq,
    manifest: Manifest,
) -> Outcome<Vec<u8>> {
    let mut bytes = Vec::with_capacity(manifest.size);
    for index in 0..manifest.count {
        cx.checkpoint().map_err(BookError::Context)?;
        let vid = fragment_vid(book.book_id, digest, index);
        let Some(row) = db.vertex_at(vid, at).map_err(KernelError::from)? else {
            return Ok(Err(invalid(format!("retained certificate fragment {index} is missing or retired"))));
        };
        if row.created_at != root.created_at {
            return Ok(Err(invalid(format!("certificate fragment {index} was not published with its immutable root"))));
        }
        let payload = match record_payload(&row, book, digest, vid) {
            Ok(payload) => payload,
            Err(refusal) => return Ok(Err(refusal)),
        };
        if let Err(refusal) = original_record(db, cx, &row)? {
            return Ok(Err(refusal));
        }
        let length = match manifest.part_len(index) {
            Ok(length) => length,
            Err(refusal) => return Ok(Err(refusal)),
        };
        match fragment_bytes(payload, index, length) {
            Ok(part) => bytes.extend_from_slice(part),
            Err(refusal) => return Ok(Err(refusal)),
        }
    }
    cx.checkpoint().map_err(BookError::Context)?;
    Ok(Ok(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_framing_has_an_independent_little_endian_vector() {
        let mut expected = b"fa:certificate-chunks:v1".to_vec();
        expected.extend_from_slice(&[
            0x01, 0x30, 0, 0, 0, 0, 0, 0, // 12_289 bytes, u64 LE
            0x00, 0x30, 0, 0,             // 12_288 bytes per fragment
            0x02, 0, 0, 0,                // two fragments
        ]);
        let manifest = Manifest::new(12_289).unwrap();
        assert_eq!(manifest.encode().unwrap(), expected);
        assert_eq!(Manifest::decode(&expected).unwrap(), Some(manifest));
        let mut expected = b"fa:certificate-fragment:v1".to_vec();
        expected.extend_from_slice(&[7, 0, 0, 0, 3, 0, 0, 0, 0x21, 0, 0xff]);
        assert_eq!(fragment(7, &[0x21, 0, 0xff]).unwrap(), expected);
        assert_eq!(fragment_bytes(&expected, 7, 3).unwrap(), [0x21, 0, 0xff]);
    }

    #[test]
    fn storage_registry_matches_the_live_limits_and_identity_domains() {
        let schema = fa_registry::toml::parse(include_str!(
            "../../../../registries/object_schemas/report_certificate_storage.toml"
        )).unwrap();
        let integer = |key| schema.root.get(key).and_then(fa_registry::toml::Value::as_int).unwrap();
        let text = |key| schema.root.get(key).and_then(fa_registry::toml::Value::as_str).unwrap();
        assert_eq!(integer("max_certificate_bytes"), MAX_CERTIFICATE_BYTES as i128);
        assert_eq!(integer("max_inline_bytes"), CHUNK_BYTES as i128);
        assert_eq!(integer("fragment_bytes"), CHUNK_BYTES as i128);
        assert_eq!(integer("max_fragments"), MAX_CERTIFICATE_BYTES.div_ceil(CHUNK_BYTES) as i128);
        assert_eq!(text("manifest_format").as_bytes(), MANIFEST_FORMAT);
        assert_eq!(text("fragment_format").as_bytes(), FRAGMENT_FORMAT);
        assert_eq!(text("fragment_identity_domain").as_bytes(), FRAGMENT_DOMAIN);
    }

    #[test]
    fn manifest_bounds_and_exact_counts_are_checked_without_allocating_the_body() {
        for size in [CHUNK_BYTES + 1, 2 * CHUNK_BYTES, 2 * CHUNK_BYTES + 1, MAX_CERTIFICATE_BYTES] {
            let manifest = Manifest::new(size).unwrap();
            assert_eq!(Manifest::decode(&manifest.encode().unwrap()).unwrap(), Some(manifest));
            assert_eq!((0..manifest.count).map(|i| manifest.part_len(i).unwrap()).sum::<usize>(), size);
            assert!(manifest.part_len(manifest.count).is_err());
        }
        for size in [0, CHUNK_BYTES, MAX_CERTIFICATE_BYTES + 1, usize::MAX] {
            assert!(Manifest::new(size).is_err());
        }
        let valid = Manifest::new(CHUNK_BYTES + 1).unwrap().encode().unwrap();
        for cut in MANIFEST_FORMAT.len()..valid.len() {
            assert!(Manifest::decode(&valid[..cut]).is_err());
        }
        for offset in [MANIFEST_FORMAT.len(), MANIFEST_FORMAT.len() + 8, MANIFEST_FORMAT.len() + 12] {
            let mut bad = valid.clone();
            bad[offset..offset + 4].fill(0xff);
            assert!(Manifest::decode(&bad).is_err());
        }
        let mut trailing = valid;
        trailing.push(0);
        assert!(Manifest::decode(&trailing).is_err());
    }

    #[test]
    fn fragment_framing_rejects_wrong_ordinals_lengths_truncation_and_trailing_bytes() {
        let body = [0x21, 0x00, 0xff];
        let encoded = fragment(7, &body).unwrap();
        assert_eq!(fragment_bytes(&encoded, 7, 3).unwrap(), body);
        assert!(fragment_bytes(&encoded, 8, 3).is_err());
        assert!(fragment_bytes(&encoded, 7, 2).is_err());
        for cut in 0..encoded.len() {
            assert!(fragment_bytes(&encoded[..cut], 7, 3).is_err());
        }
        let mut trailing = encoded;
        trailing.push(0);
        assert!(fragment_bytes(&trailing, 7, 3).is_err());
        assert!(fragment(0, &[]).is_err());
        assert!(fragment(0, &vec![0; CHUNK_BYTES + 1]).is_err());
    }

    #[test]
    fn fragment_identity_binds_book_full_digest_and_position_separately_from_the_root() {
        let book = Id128([1; 16]);
        let digest = [2; 32];
        let original = fragment_vid(book, &digest, 0);
        assert_ne!(original, certificate_vid(book, &digest));
        assert_ne!(original, fragment_vid(Id128([3; 16]), &digest, 0));
        let mut other = digest;
        other[31] ^= 1;
        assert_ne!(original, fragment_vid(book, &other, 0));
        assert_ne!(original, fragment_vid(book, &digest, 1));
    }
}
