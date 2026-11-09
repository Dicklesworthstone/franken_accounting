//! Bounded framing for an optional PPA equity comparison. No amount is folded
//! here: the facade replays both original v2 sources against the independently
//! supplied complete request and validates the actual case posting period.

use super::*;

pub(super) const FORMAT: &[u8] = b"fa:equity-roll-forward-diff-certificate:v1";
const DOMAIN: &[u8] = b"fa:equity-roll-forward-diff-certificate-digest:v1";
const EQUITY_FORMAT: &[u8] = b"fa:equity-roll-forward-certificate:v2";
const EQUITY_DOMAIN: &[u8] = b"fa:equity-roll-forward-certificate-digest:v2";
const ROLL_FORMAT: &[u8] = b"fa:roll-forward-certificate:v1";
const ROLL_DOMAIN: &[u8] = b"fa:roll-forward-certificate-digest:v1";
const NATIVE_FORMAT: &[u8] = b"fa:report-certificate:v1";
const OUTPUT_FORMAT: &[u8] = b"fa:equity-roll-forward-diff:v1";
const STATEMENT_FORMAT: &[u8] = b"fa:equity-roll-forward:v2";
const MAX_SCOPE: usize = 4096;

struct Source<'a> {
    book: Id128,
    branch: Id128,
    at: CommitSeq,
    scope: &'a [u8],
    units: &'a [u8],
    label: &'a str,
    from: i32,
    through: i32,
    roles: &'a [u8],
}

fn finish_digest(mut r: Reader<'_>, bytes: &[u8], domain: &[u8]) -> Result<[u8; 32], DecodeError> {
    let body_len = r.offset();
    let digest = r.fixed("content digest")?;
    if domain_digest(domain, &[&bytes[..body_len]]) != digest {
        return Err(r.invalid("content digest"));
    }
    r.finish()?;
    Ok(digest)
}

fn ids<'a>(r: &mut Reader<'a>, bytes: &'a [u8], required: bool) -> Result<&'a [u8], DecodeError> {
    let start = r.offset();
    let count = r.count(MAX_SCOPE, "account scope")?;
    if required && count == 0 {
        return Err(r.invalid("nonempty account scope"));
    }
    let mut prior = None;
    for _ in 0..count {
        let id = r.u128("account")?;
        if prior.is_some_and(|before| before >= id) {
            return Err(r.invalid("strictly increasing account scope"));
        }
        prior = Some(id);
    }
    Ok(&bytes[start..r.offset()])
}

fn units<'a>(r: &mut Reader<'a>, bytes: &'a [u8]) -> Result<&'a [u8], DecodeError> {
    let start = r.offset();
    let count = r.count(MAX_SCOPE, "unit scope")?;
    if count == 0 {
        return Err(r.invalid("nonempty unit scope"));
    }
    let mut prior = None;
    for _ in 0..count {
        let unit = r.u32("unit")?;
        if prior.is_some_and(|before| before >= unit) {
            return Err(r.invalid("strictly increasing unit scope"));
        }
        prior = Some(unit);
    }
    Ok(&bytes[start..r.offset()])
}

fn native(bytes: &[u8]) -> Result<(Id128, Id128, CommitSeq, i32), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.fixed::<{ NATIVE_FORMAT.len() }>("native format")? != NATIVE_FORMAT {
        return Err(r.invalid("sequence-selected native equity source"));
    }
    for (field, expected) in [
        ("replay scope", "fa-fold-over-prefix"),
        ("authority", "embedded-owner"),
        ("output format", "fa:trial-balance:v1"),
    ] {
        if r.str(64, field)? != expected {
            return Err(r.invalid(field));
        }
    }
    let book = Id128(r.fixed("native book")?);
    let branch = Id128(r.fixed("native branch")?);
    let at = CommitSeq(r.u64("native frontier")?);
    if r.u8("native selector")? != 1 {
        return Err(r.invalid("native closing-stock selector"));
    }
    let through = r.i32("native through")?;
    r.fixed::<32>("registry closure")?;
    r.fixed::<32>("journal root")?;
    r.u64("journal leaves")?;
    let count = r.count(11, "native inputs")?;
    if count < 7 {
        return Err(r.invalid("complete native input framing"));
    }
    for _ in 0..count {
        r.bytes(MAX_NATIVE_BYTES, "native input")?;
    }
    r.bytes(MAX_BYTES, "native output")?;
    r.fixed::<32>("native output digest")?;
    r.fixed::<32>("native certificate digest")?;
    r.finish()?;
    Ok((book, branch, at, through))
}

fn roll(bytes: &[u8]) -> Result<Source<'_>, DecodeError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "roll-forward format")? != ROLL_FORMAT {
        return Err(r.invalid("roll-forward certificate format"));
    }
    let (book, branch, at, native_through) = native(r.bytes(MAX_BYTES, "roll-forward source")?)?;
    let start = r.offset();
    ids(&mut r, bytes, true)?;
    let units = units(&mut r, bytes)?;
    let label = r.str(256, "roll-forward label")?;
    let from = r.i32("roll-forward from")?;
    let through = r.i32("roll-forward through")?;
    if label.trim().is_empty() || from > through || through != native_through {
        return Err(r.invalid("complete roll-forward date and label selection"));
    }
    let scope = &bytes[start..r.offset()];
    let output = r.bytes(MAX_BYTES, "roll-forward output")?;
    let mut header = Reader::new(output);
    if header.fixed::<16>("roll-forward magic")? != *b"FA-ROLL-FORWARD\0"
        || header.u16("roll-forward major")? != 1
        || header.u16("roll-forward minor")? != 0
        || Id128(header.fixed("roll-forward book")?) != book
        || Id128(header.fixed("roll-forward branch")?) != branch
        || CommitSeq(header.u64("roll-forward frontier")?) != at
        || header.str(256, "roll-forward label")? != label
        || header.i32("roll-forward from")? != from
        || header.i32("roll-forward through")? != through
    {
        return Err(header.invalid("roll-forward source and output coordinates"));
    }
    finish_digest(r, bytes, ROLL_DOMAIN)?;
    Ok(Source {
        book,
        branch,
        at,
        scope,
        units,
        label,
        from,
        through,
        roles: &[],
    })
}

fn source(bytes: &[u8]) -> Result<Source<'_>, DecodeError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "equity source format")? != EQUITY_FORMAT {
        return Err(r.invalid("original v2 equity certificate"));
    }
    let mut source = roll(r.bytes(MAX_BYTES, "equity roll-forward source")?)?;
    let start = r.offset();
    let issuance = ids(&mut r, bytes, false)?;
    let distribution = ids(&mut r, bytes, false)?;
    source.roles = &bytes[start..r.offset()];
    // Both vectors are already sorted and bounded. Refuse an account given
    // two contradictory owner roles without allocating source copies.
    let mut a = Reader::new(issuance);
    let mut b = Reader::new(distribution);
    let mut an = a.count(MAX_SCOPE, "issuance roles")?;
    let mut bn = b.count(MAX_SCOPE, "distribution roles")?;
    let mut av = if an > 0 {
        Some(a.u128("issuance")?)
    } else {
        None
    };
    let mut bv = if bn > 0 {
        Some(b.u128("distribution")?)
    } else {
        None
    };
    while let (Some(ai), Some(bi)) = (av, bv) {
        if ai == bi {
            return Err(r.invalid("disjoint equity owner roles"));
        }
        if ai < bi {
            an -= 1;
            av = if an > 0 {
                Some(a.u128("issuance")?)
            } else {
                None
            };
        } else {
            bn -= 1;
            bv = if bn > 0 {
                Some(b.u128("distribution")?)
            } else {
                None
            };
        }
    }
    let mut output = Reader::new(r.bytes(MAX_BYTES, "equity output")?);
    if output.bytes(64, "equity output format")? != b"fa:equity-roll-forward-report:v2" {
        return Err(output.invalid("equity output version"));
    }
    let mut statement = Reader::new(output.bytes(MAX_BYTES, "equity statement")?);
    if statement.fixed::<{ STATEMENT_FORMAT.len() }>("equity statement format")? != STATEMENT_FORMAT
        || Id128(statement.fixed("equity book")?) != source.book
        || Id128(statement.fixed("equity branch")?) != source.branch
        || CommitSeq(statement.u64("equity frontier")?) != source.at
        || statement.str(256, "equity label")? != source.label
        || statement.i32("equity from")? != source.from
        || statement.i32("equity through")? != source.through
    {
        return Err(statement.invalid("equity source and output coordinates"));
    }
    let mut expected_units = Reader::new(source.units);
    let count = expected_units.count(MAX_SCOPE, "equity units")?;
    if statement.count(MAX_SCOPE, "equity output units")? != count {
        return Err(statement.invalid("complete equity output units"));
    }
    for _ in 0..count {
        if statement.u32("equity output unit")? != expected_units.u32("equity unit")? {
            return Err(statement.invalid("equity output unit order"));
        }
        for _ in 0..15 {
            statement.i128("equity amount")?;
        }
    }
    statement.finish()?;
    finish_digest(r, bytes, EQUITY_DOMAIN)?;
    Ok(source)
}

pub(super) fn validate(
    book: Id128,
    post: DisclosurePost,
    digest: [u8; 32],
    bytes: &[u8],
) -> Result<(), DecodeError> {
    let mut r = Reader::new(bytes);
    if r.bytes(64, "equity comparison format")? != FORMAT {
        return Err(r.invalid("equity comparison format"));
    }
    let before = source(r.bytes(MAX_BYTES, "before equity source")?)?;
    let after = source(r.bytes(MAX_BYTES, "after equity source")?)?;
    if before.book != book
        || after.book != book
        || before.branch != Id128::TRUNK
        || after.branch != Id128::TRUNK
        || before.at.0.checked_add(1) != Some(post.recorded_at.0)
        || after.at != post.recorded_at
        || before.scope != after.scope
        || before.roles != after.roles
    {
        return Err(r.invalid(
            "same complete equity question immediately before and at the exact case Post",
        ));
    }
    r.u128("equity comparison producer")?;
    r.fixed::<32>("equity comparison capability")?;
    let mut output = Reader::new(r.bytes(MAX_BYTES, "equity comparison output")?);
    if output.bytes(64, "equity comparison output format")? != OUTPUT_FORMAT
        || Id128(output.fixed("comparison book")?) != book
        || Id128(output.fixed("comparison branch")?) != Id128::TRUNK
        || CommitSeq(output.u64("comparison before")?) != before.at
        || CommitSeq(output.u64("comparison after")?) != after.at
    {
        return Err(output.invalid("equity comparison output coordinates"));
    }
    output.fixed::<32>("before output digest")?;
    output.fixed::<32>("after output digest")?;
    if output.str(256, "comparison label")? != before.label
        || output.i32("comparison from")? != before.from
        || output.i32("comparison through")? != before.through
    {
        return Err(output.invalid("equity comparison output selection"));
    }
    let mut units = Reader::new(before.units);
    let count = units.count(MAX_SCOPE, "comparison units")?;
    if output.count(MAX_SCOPE, "comparison output units")? != count {
        return Err(output.invalid("complete equity comparison output units"));
    }
    for _ in 0..count {
        if output.u32("comparison output unit")? != units.u32("comparison unit")? {
            return Err(output.invalid("equity comparison output unit order"));
        }
        for _ in 0..45 {
            output.i128("comparison amount")?;
        }
    }
    output.finish()?;
    if finish_digest(r, bytes, DOMAIN)? != digest {
        return Err(Reader::new(bytes).invalid("expected equity comparison digest"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use fa_model::Writer;
    use fgdb_types::VId;

    use super::*;

    const BOOK: Id128 = Id128([9; 16]);
    const POST: DisclosurePost = DisclosurePost {
        entry: VId(27),
        recorded_at: CommitSeq(30),
    };

    fn sealed(w: Writer, domain: &[u8]) -> Vec<u8> {
        let mut bytes = w.finish().unwrap();
        bytes.extend_from_slice(&domain_digest(domain, &[&bytes]));
        bytes
    }

    // Deliberately opaque native proofs exercise only framing; the facade's
    // real PPA lifecycle test feeds this parser actual replayable certificates.
    fn framed_source(at: u64, unit: u32, role: u128, through: i32) -> Vec<u8> {
        let mut native = Writer::new();
        native
            .fixed(NATIVE_FORMAT)
            .str("fa-fold-over-prefix")
            .str("embedded-owner")
            .str("fa:trial-balance:v1")
            .fixed(&BOOK.0)
            .fixed(&Id128::TRUNK.0)
            .u64(at)
            .u8(1)
            .i32(through)
            .fixed(&[1; 32])
            .fixed(&[2; 32])
            .u64(1)
            .u32(7);
        for _ in 0..7 {
            native.bytes(b"opaque native proof");
        }
        native
            .bytes(b"opaque native amount output")
            .fixed(&[3; 32])
            .fixed(&[4; 32]);
        let native = native.finish().unwrap();
        let mut output = Writer::new();
        output
            .fixed(b"FA-ROLL-FORWARD\0")
            .u16(1)
            .u16(0)
            .fixed(&BOOK.0)
            .fixed(&Id128::TRUNK.0)
            .u64(at)
            .str("equity")
            .i32(0)
            .i32(through);
        let mut roll = Writer::new();
        roll.bytes(ROLL_FORMAT)
            .bytes(&native)
            .u32(2)
            .u128(1)
            .u128(2)
            .u32(1)
            .u32(unit)
            .str("equity")
            .i32(0)
            .i32(through)
            .bytes(&output.finish().unwrap());
        let roll = sealed(roll, ROLL_DOMAIN);
        let mut statement = Writer::new();
        statement
            .fixed(STATEMENT_FORMAT)
            .fixed(&BOOK.0)
            .fixed(&Id128::TRUNK.0)
            .u64(at)
            .str("equity")
            .i32(0)
            .i32(through)
            .u32(1)
            .u32(unit);
        for _ in 0..15 {
            statement.i128(0);
        }
        let mut output = Writer::new();
        output
            .bytes(b"fa:equity-roll-forward-report:v2")
            .bytes(&statement.finish().unwrap());
        let mut equity = Writer::new();
        equity
            .bytes(EQUITY_FORMAT)
            .bytes(&roll)
            .u32(1)
            .u128(role)
            .u32(0)
            .bytes(&output.finish().unwrap());
        sealed(equity, EQUITY_DOMAIN)
    }

    fn framed_comparison(before: &[u8], after: &[u8]) -> ([u8; 32], Vec<u8>) {
        let mut output = Writer::new();
        output
            .bytes(OUTPUT_FORMAT)
            .fixed(&BOOK.0)
            .fixed(&Id128::TRUNK.0)
            .u64(29)
            .u64(30)
            .fixed(&[5; 32])
            .fixed(&[6; 32])
            .str("equity")
            .i32(0)
            .i32(31)
            .u32(1)
            .u32(1);
        for _ in 0..45 {
            output.i128(0);
        }
        let mut certificate = Writer::new();
        certificate
            .bytes(FORMAT)
            .bytes(before)
            .bytes(after)
            .u128(7)
            .fixed(&[8; 32])
            .bytes(&output.finish().unwrap());
        let bytes = sealed(certificate, DOMAIN);
        let digest = bytes[bytes.len() - 32..].try_into().unwrap();
        (digest, bytes)
    }

    #[test]
    fn equity_disclosure_framing_binds_both_post_frontiers_and_the_complete_question() {
        let before = framed_source(29, 1, 2, 31);
        let after = framed_source(30, 1, 2, 31);
        let (digest, bytes) = framed_comparison(&before, &after);
        assert!(super::super::validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_ok());
        for (before, after) in [
            (framed_source(28, 1, 2, 31), after.clone()),
            (before.clone(), framed_source(31, 1, 2, 31)),
            (before.clone(), framed_source(30, 2, 2, 31)),
            (before.clone(), framed_source(30, 1, 3, 31)),
            (before.clone(), framed_source(30, 1, 2, 32)),
        ] {
            let (digest, bytes) = framed_comparison(&before, &after);
            assert!(
                super::super::validate_disclosure_comparison(BOOK, POST, digest, &bytes).is_err()
            );
        }
        assert!(
            super::super::validate_disclosure_comparison(Id128([8; 16]), POST, digest, &bytes)
                .is_err()
        );
        assert!(super::super::validate_disclosure_comparison(BOOK, POST, [7; 32], &bytes).is_err());
        for cut in [0, 4, FORMAT.len(), bytes.len() / 2, bytes.len() - 1] {
            assert!(
                super::super::validate_disclosure_comparison(BOOK, POST, digest, &bytes[..cut])
                    .is_err()
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(
            super::super::validate_disclosure_comparison(BOOK, POST, digest, &trailing).is_err()
        );
        let mut changed = bytes;
        let middle = changed.len() / 2;
        changed[middle] ^= 1;
        assert!(
            super::super::validate_disclosure_comparison(BOOK, POST, digest, &changed).is_err()
        );
    }
}
