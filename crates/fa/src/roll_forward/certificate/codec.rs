//! Bounded composition of an existing native certificate and exact report bytes.

use fa_model::{DecodeError, Id128, Reader, Writer, domain_digest};
use fa_time::DateDay;

use super::*;
use crate::ReportSelection;

pub(super) fn normalize(
    request: &RollForwardRequest,
    at: CommitSeq,
) -> Result<RollForwardRequest, Refusal> {
    // Bound and reject duplicates BEFORE copying any caller-controlled vectors.
    let (accounts, units) = super::super::scope(request)?;
    Ok(RollForwardRequest {
        accounts: accounts.into_iter().collect(),
        units: units.into_iter().collect(),
        label: request.label.clone(),
        effective_from: request.effective_from,
        effective_through: request.effective_through,
        known_at: Some(at),
    })
}

fn write_request(w: &mut Writer, request: &RollForwardRequest) {
    // The recorded prefix is carried exactly once, by the source certificate.
    w.list(&request.accounts, |w, account| {
        w.u128(account.0);
    })
    .list(&request.units, |w, unit| {
        w.u32(*unit);
    })
    .str(&request.label)
    .i32(request.effective_from.0)
    .i32(request.effective_through.0);
}

fn read_request(r: &mut Reader<'_>, at: CommitSeq) -> Result<RollForwardRequest, DecodeError> {
    let count = r.count(4096, "roll-forward accounts")?;
    if count == 0 || count > r.remaining() / 16 {
        return Err(r.invalid("empty or truncated roll-forward accounts"));
    }
    let mut accounts = Vec::with_capacity(count);
    for _ in 0..count {
        accounts.push(VId(r.u128("roll-forward account")?));
    }
    let count = r.count(4096, "roll-forward units")?;
    if count == 0 || count > r.remaining() / 4 {
        return Err(r.invalid("empty or truncated roll-forward units"));
    }
    let mut units = Vec::with_capacity(count);
    for _ in 0..count {
        units.push(r.u32("roll-forward unit")?);
    }
    if accounts.windows(2).any(|pair| pair[0] >= pair[1])
        || units.windows(2).any(|pair| pair[0] >= pair[1])
    {
        return Err(r.invalid("roll-forward scope must be strictly increasing"));
    }
    Ok(RollForwardRequest {
        accounts,
        units,
        label: r.str(256, "roll-forward label")?.to_string(),
        effective_from: DateDay(r.i32("roll-forward from")?),
        effective_through: DateDay(r.i32("roll-forward through")?),
        known_at: Some(at),
    })
}

/// Check the existing report envelope without inventing a second report codec.
/// The remaining bytes are opaque here: only native replay verifies their
/// meaning, completeness and exact canonical representation.
fn check_header(
    bytes: &[u8],
    book: Id128,
    request: &RollForwardRequest,
) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<16>("roll-forward magic")? != *b"FA-ROLL-FORWARD\0"
        || r.u16("roll-forward major")? != 1
        || r.u16("roll-forward minor")? != 0
        || r.fixed::<16>("roll-forward book")? != book.0
        || r.fixed::<16>("roll-forward branch")? != Id128::TRUNK.0
        || Some(CommitSeq(r.u64("roll-forward known-at")?)) != request.known_at
        || r.str(256, "roll-forward label")? != request.label
        || r.i32("roll-forward from")? != request.effective_from.0
        || r.i32("roll-forward through")? != request.effective_through.0
    {
        return Err(r.invalid("roll-forward output header differs from its certificate"));
    }
    Ok(())
}

impl RollForwardCertificate {
    fn body_bytes(&self) -> Result<Vec<u8>, Refusal> {
        if self.output.len() > MAX_ROLL_FORWARD_CERTIFICATE_BYTES {
            return Err(invalid("roll-forward output exceeds the format limit"));
        }
        if self.source.branch_id != Id128::TRUNK
            || self.source.time_selection.is_some()
            || self.source.selection
                != ReportSelection::TrialBalance(TrialBalanceSelection::AsOf(
                    self.request.effective_through,
                ))
            || self.request.known_at != Some(self.source.known_at)
            || normalize(&self.request, self.source.known_at)? != self.request
        {
            return Err(invalid(
                "roll-forward source or explicit selector is not canonical",
            ));
        }
        check_header(&self.output, self.source.book_id, &self.request)
            .map_err(|error| invalid(error.to_string()))?;
        let source = self
            .source
            .canonical_bytes()
            .map_err(|error| invalid(error.to_string()))?;
        // Its public fields are mutable to embeddings; encoding is not validation.
        ReportCertificate::decode(&source)?;
        let size = [
            4,
            ROLL_FORWARD_CERTIFICATE_FORMAT.len(),
            4,
            source.len(),
            4,
            self.request.accounts.len() * 16,
            4,
            self.request.units.len() * 4,
            4,
            self.request.label.len(),
            8,
            4,
            self.output.len(),
            32,
        ]
        .into_iter()
        .try_fold(0_usize, |total, part| total.checked_add(part))
        .ok_or_else(|| invalid("roll-forward certificate length overflow"))?;
        if size > MAX_ROLL_FORWARD_CERTIFICATE_BYTES {
            return Err(invalid(
                "roll-forward certificate exceeds its 64 MiB total bound",
            ));
        }
        let mut w = Writer::with_capacity(size);
        w.bytes(ROLL_FORWARD_CERTIFICATE_FORMAT).bytes(&source);
        write_request(&mut w, &self.request);
        w.bytes(&self.output);
        w.finish().map_err(|error| invalid(error.to_string()))
    }

    pub(super) fn seal(
        source: ReportCertificate,
        request: RollForwardRequest,
        output: Vec<u8>,
    ) -> Result<Self, Refusal> {
        let mut value = Self {
            source,
            request,
            output,
            digest: [0; 32],
        };
        value.digest = domain_digest(DIGEST_DOMAIN, &[&value.body_bytes()?]);
        Ok(value)
    }

    /// Framing and unkeyed content integrity, NOT a successful historical replay.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Refusal> {
        let mut body = self.body_bytes()?;
        if domain_digest(DIGEST_DOMAIN, &[&body]) != self.digest {
            return Err(invalid("roll-forward certificate content digest differs"));
        }
        body.extend_from_slice(&self.digest);
        Ok(body)
    }

    /// Bound all lengths and list allocations, reject alternate scope ordering,
    /// validate the nested certificate and exact outer digest. Report contents
    /// remain untrusted until replay against the independently opened book.
    pub fn decode(bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() > MAX_ROLL_FORWARD_CERTIFICATE_BYTES {
            return Err(invalid(
                "roll-forward certificate exceeds its 64 MiB total bound",
            ));
        }
        let malformed =
            |error: DecodeError| invalid(format!("malformed roll-forward certificate: {error}"));
        let mut r = Reader::new(bytes);
        if r.bytes(64, "roll-forward certificate format")
            .map_err(malformed)?
            != ROLL_FORWARD_CERTIFICATE_FORMAT
        {
            return Err(invalid("unsupported roll-forward certificate format"));
        }
        let source = ReportCertificate::decode(
            r.bytes(MAX_ROLL_FORWARD_CERTIFICATE_BYTES, "roll-forward source")
                .map_err(malformed)?,
        )?;
        let request = read_request(&mut r, source.known_at).map_err(malformed)?;
        let output = r
            .bytes(MAX_ROLL_FORWARD_CERTIFICATE_BYTES, "roll-forward output")
            .map_err(malformed)?
            .to_vec();
        let digest = r
            .fixed("roll-forward certificate digest")
            .map_err(malformed)?;
        r.finish().map_err(malformed)?;
        let value = Self {
            source,
            request,
            output,
            digest,
        };
        if value.canonical_bytes()?.as_slice() != bytes {
            return Err(invalid("noncanonical roll-forward certificate encoding"));
        }
        Ok(value)
    }
}
