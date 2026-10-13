//! A canonical-byte reader under the model's encoding laws (plan Appendix A):
//! little-endian fixed-width integers, a `u32` length before every
//! variable-length field, a `u32` count before every list, a `u8` presence
//! tag (`0` or `1`) before every option, and no trailing bytes. Every length
//! is checked against the bytes that remain before anything is allocated.
//!
//! Written for this crate: the verifier shares no decoder with the producer.

use core::fmt;

/// Why a decode stopped, with the byte offset it stopped at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodeError {
    pub offset: usize,
    pub what: &'static str,
    pub reason: Reason,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Truncated,
    TooLong { max: usize, actual: usize },
    BadTag(u8),
    Trailing,
    Unsorted,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decode `{}` at byte {}: ", self.what, self.offset)?;
        match self.reason {
            Reason::Truncated => write!(f, "input ends early"),
            Reason::TooLong { max, actual } => write!(f, "length {actual} exceeds bound {max}"),
            Reason::BadTag(t) => write!(f, "unknown tag {t}"),
            Reason::Trailing => write!(f, "trailing bytes after the value"),
            Reason::Unsorted => write!(f, "collection is not strictly ascending"),
        }
    }
}

impl core::error::Error for DecodeError {}

pub(crate) struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf, at: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.at
    }

    pub(crate) fn error(&self, what: &'static str, reason: Reason) -> DecodeError {
        DecodeError {
            offset: self.at,
            what,
            reason,
        }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(self.error(what, Reason::Truncated));
        }
        let out = &self.buf[self.at..self.at + n];
        self.at += n;
        Ok(out)
    }

    pub(crate) fn fixed<const N: usize>(
        &mut self,
        what: &'static str,
    ) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N, what)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self, what: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, what)?[0])
    }

    pub(crate) fn u16(&mut self, what: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.fixed(what)?))
    }

    pub(crate) fn u32(&mut self, what: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.fixed(what)?))
    }

    pub(crate) fn u64(&mut self, what: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.fixed(what)?))
    }

    pub(crate) fn u128(&mut self, what: &'static str) -> Result<u128, DecodeError> {
        Ok(u128::from_le_bytes(self.fixed(what)?))
    }

    pub(crate) fn i32(&mut self, what: &'static str) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.fixed(what)?))
    }

    pub(crate) fn i128(&mut self, what: &'static str) -> Result<i128, DecodeError> {
        Ok(i128::from_le_bytes(self.fixed(what)?))
    }

    fn length(&mut self, max: usize, what: &'static str) -> Result<usize, DecodeError> {
        let n = usize::try_from(self.u32(what)?).unwrap_or(usize::MAX);
        if n > max {
            return Err(self.error(what, Reason::TooLong { max, actual: n }));
        }
        Ok(n)
    }

    /// A `u32`-length-prefixed byte string of at most `max` bytes.
    pub(crate) fn bytes(
        &mut self,
        max: usize,
        what: &'static str,
    ) -> Result<&'a [u8], DecodeError> {
        let n = self.length(max, what)?;
        self.take(n, what)
    }

    /// A `u32` element count of at most `max`, where every element occupies
    /// at least `min_element_bytes` — so a hostile count cannot make the
    /// caller allocate beyond what the input could possibly hold.
    pub(crate) fn count(
        &mut self,
        max: usize,
        min_element_bytes: usize,
        what: &'static str,
    ) -> Result<usize, DecodeError> {
        let n = self.length(max, what)?;
        if n.saturating_mul(min_element_bytes.max(1)) > self.remaining() {
            return Err(self.error(what, Reason::Truncated));
        }
        Ok(n)
    }

    /// The presence tag of an option.
    pub(crate) fn present(&mut self, what: &'static str) -> Result<bool, DecodeError> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(self.error(what, Reason::BadTag(t))),
        }
    }

    pub(crate) fn finish(self, what: &'static str) -> Result<(), DecodeError> {
        if self.remaining() != 0 {
            return Err(self.error(what, Reason::Trailing));
        }
        Ok(())
    }
}

/// Little-endian canonical bytes, the writer half the verifier needs to
/// recompute an envelope from a payload.
#[derive(Default)]
pub(crate) struct Writer {
    pub(crate) buf: Vec<u8>,
}

impl Writer {
    pub(crate) fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub(crate) fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn u128(&mut self, v: u128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    #[cfg(test)]
    pub(crate) fn i128(&mut self, v: i128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub(crate) fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    /// A byte string already bounded by its caller, with canonical framing.
    #[cfg(test)]
    pub(crate) fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.count(b.len()).fixed(b)
    }

    /// A list count. Every list the verifier writes is bounded far below
    /// `u32::MAX` by the decoder that produced it.
    pub(crate) fn count(&mut self, n: usize) -> &mut Self {
        self.u32(u32::try_from(n).unwrap_or(u32::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reader_refuses_truncation_bad_tags_overlong_lists_and_trailing_bytes() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u32("x").unwrap_err().reason, Reason::Truncated);

        let mut r = Reader::new(&[2]);
        assert_eq!(r.present("opt").unwrap_err().reason, Reason::BadTag(2));

        // A count of 3 sixteen-byte elements with only 16 bytes behind it.
        let mut bytes = 3u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&[0; 16]);
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.count(10, 16, "list").unwrap_err().reason,
            Reason::Truncated
        );
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.count(2, 16, "list").unwrap_err().reason,
            Reason::TooLong { max: 2, actual: 3 }
        );

        let r = Reader::new(&[0]);
        assert_eq!(r.finish("value").unwrap_err().reason, Reason::Trailing);

        let mut w = Writer::default();
        w.u8(1)
            .u16(2)
            .u32(3)
            .u64(4)
            .u128(5)
            .i32(-6)
            .fixed(&[7])
            .count(8);
        let mut r = Reader::new(&w.buf);
        assert_eq!(r.u8("a").unwrap(), 1);
        assert_eq!(r.u16("b").unwrap(), 2);
        assert_eq!(r.u32("c").unwrap(), 3);
        assert_eq!(r.u64("d").unwrap(), 4);
        assert_eq!(r.u128("e").unwrap(), 5);
        assert_eq!(r.i32("f").unwrap(), -6);
        assert_eq!(r.fixed::<1>("g").unwrap(), [7]);
        assert_eq!(r.u32("h").unwrap(), 8);
        r.finish("all").unwrap();
    }

    #[test]
    fn proof_fields_preserve_signed_boundaries_and_binary_string_framing() {
        for amount in [i128::MIN, -1, 0, 1, i128::MAX] {
            let mut w = Writer::default();
            w.i128(amount).bytes(&[]).bytes(&[0, 255, 128]);
            assert_eq!(&w.buf[..16], &amount.to_le_bytes());
            assert_eq!(&w.buf[16..20], &0u32.to_le_bytes());
            assert_eq!(&w.buf[20..24], &3u32.to_le_bytes());
            let mut r = Reader::new(&w.buf);
            assert_eq!(r.i128("amount").unwrap(), amount);
            assert!(r.bytes(0, "empty").unwrap().is_empty());
            assert_eq!(r.bytes(3, "binary").unwrap(), &[0, 255, 128]);
            r.finish("proof fields").unwrap();
        }
    }
}
