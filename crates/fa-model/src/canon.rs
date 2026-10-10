//! The canonical byte codec (plan Appendix A encoding laws).
//!
//! Little-endian fixed-width integers; `u32` byte-length before every
//! variable-length field; `u32` count before every list; `u8` presence tag
//! before every option; no floats; no varints (no field in the model says
//! varint). Lengths are checked against the caller's bound and against the
//! bytes that remain *before* anything is allocated. A reader refuses
//! trailing bytes. Encoding never panics: a length that does not fit `u32`
//! is reported by `finish`.

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
    BadUtf8,
    Trailing,
    Unsorted,
    Invalid,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decode `{}` at byte {}: ", self.what, self.offset)?;
        match self.reason {
            Reason::Truncated => write!(f, "input ends early"),
            Reason::TooLong { max, actual } => write!(f, "length {actual} exceeds bound {max}"),
            Reason::BadTag(t) => write!(f, "unknown tag {t}"),
            Reason::BadUtf8 => write!(f, "not UTF-8"),
            Reason::Trailing => write!(f, "trailing bytes after the value"),
            Reason::Unsorted => write!(f, "collection is not strictly ascending"),
            Reason::Invalid => write!(f, "value violates the schema"),
        }
    }
}

impl core::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// A byte length or count did not fit the `u32` prefix.
    LengthOverflow,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthOverflow => write!(f, "a length does not fit the u32 prefix"),
        }
    }
}

impl core::error::Error for EncodeError {}

/// Appends canonical bytes. Infallible per call; an unrepresentable length
/// is remembered and reported by [`Writer::finish`].
#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
    overflow: bool,
}

impl Writer {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_capacity(n: usize) -> Self {
        Self {
            buf: Vec::with_capacity(n),
            overflow: false,
        }
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(u8::from(v))
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn u128(&mut self, v: u128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i32(&mut self, v: i32) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    pub fn i128(&mut self, v: i128) -> &mut Self {
        self.buf.extend_from_slice(&v.to_le_bytes());
        self
    }

    /// Raw bytes whose length the schema fixes (digests, 16-byte ids).
    pub fn fixed(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    fn len_prefix(&mut self, n: usize) {
        match u32::try_from(n) {
            Ok(n) => {
                self.u32(n);
            }
            Err(_) => self.overflow = true,
        }
    }

    /// `u32` length then the bytes.
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.len_prefix(b.len());
        self.buf.extend_from_slice(b);
        self
    }

    /// `u32` byte length then the UTF-8 bytes.
    pub fn str(&mut self, s: &str) -> &mut Self {
        self.bytes(s.as_bytes())
    }

    /// `u8` presence tag, then the value when present.
    pub fn opt<T>(&mut self, v: Option<&T>, f: impl FnOnce(&mut Self, &T)) -> &mut Self {
        match v {
            None => {
                self.u8(0);
            }
            Some(v) => {
                self.u8(1);
                f(self, v);
            }
        }
        self
    }

    /// `u32` count then each item.
    pub fn list<T>(&mut self, items: &[T], mut f: impl FnMut(&mut Self, &T)) -> &mut Self {
        self.len_prefix(items.len());
        for item in items {
            f(self, item);
        }
        self
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn finish(self) -> Result<Vec<u8>, EncodeError> {
        if self.overflow {
            Err(EncodeError::LengthOverflow)
        } else {
            Ok(self.buf)
        }
    }
}

/// Reads canonical bytes with bounds checked before allocation.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    #[must_use]
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    #[must_use]
    pub fn offset(&self) -> usize {
        self.pos
    }

    #[must_use]
    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn err(&self, what: &'static str, reason: Reason) -> DecodeError {
        DecodeError {
            offset: self.pos,
            what,
            reason,
        }
    }

    fn take(&mut self, n: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        if n > self.remaining() {
            return Err(self.err(what, Reason::Truncated));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self, what: &'static str) -> Result<u8, DecodeError> {
        Ok(self.take(1, what)?[0])
    }

    pub fn bool(&mut self, what: &'static str) -> Result<bool, DecodeError> {
        match self.u8(what)? {
            0 => Ok(false),
            1 => Ok(true),
            t => Err(DecodeError {
                offset: self.pos - 1,
                what,
                reason: Reason::BadTag(t),
            }),
        }
    }

    pub fn fixed<const N: usize>(&mut self, what: &'static str) -> Result<[u8; N], DecodeError> {
        let s = self.take(N, what)?;
        let mut out = [0u8; N];
        out.copy_from_slice(s);
        Ok(out)
    }

    pub fn u16(&mut self, what: &'static str) -> Result<u16, DecodeError> {
        Ok(u16::from_le_bytes(self.fixed(what)?))
    }

    pub fn u32(&mut self, what: &'static str) -> Result<u32, DecodeError> {
        Ok(u32::from_le_bytes(self.fixed(what)?))
    }

    pub fn u64(&mut self, what: &'static str) -> Result<u64, DecodeError> {
        Ok(u64::from_le_bytes(self.fixed(what)?))
    }

    pub fn u128(&mut self, what: &'static str) -> Result<u128, DecodeError> {
        Ok(u128::from_le_bytes(self.fixed(what)?))
    }

    pub fn i32(&mut self, what: &'static str) -> Result<i32, DecodeError> {
        Ok(i32::from_le_bytes(self.fixed(what)?))
    }

    pub fn i64(&mut self, what: &'static str) -> Result<i64, DecodeError> {
        Ok(i64::from_le_bytes(self.fixed(what)?))
    }

    pub fn i128(&mut self, what: &'static str) -> Result<i128, DecodeError> {
        Ok(i128::from_le_bytes(self.fixed(what)?))
    }

    /// A `u32`-prefixed byte string of at most `max` bytes.
    pub fn bytes(&mut self, max: usize, what: &'static str) -> Result<&'a [u8], DecodeError> {
        let n = self.u32(what)? as usize;
        if n > max {
            return Err(self.err(what, Reason::TooLong { max, actual: n }));
        }
        self.take(n, what)
    }

    /// A `u32`-prefixed UTF-8 string of at most `max` bytes.
    pub fn str(&mut self, max: usize, what: &'static str) -> Result<&'a str, DecodeError> {
        let start = self.pos;
        let b = self.bytes(max, what)?;
        core::str::from_utf8(b).map_err(|_| DecodeError {
            offset: start,
            what,
            reason: Reason::BadUtf8,
        })
    }

    /// A `u32` item count of at most `max`, and never more than the bytes
    /// that remain (every item occupies at least one byte), so a hostile
    /// count cannot drive an allocation.
    pub fn count(&mut self, max: usize, what: &'static str) -> Result<usize, DecodeError> {
        let n = self.u32(what)? as usize;
        if n > max {
            return Err(self.err(what, Reason::TooLong { max, actual: n }));
        }
        if n > self.remaining() {
            return Err(self.err(what, Reason::Truncated));
        }
        Ok(n)
    }

    pub fn list<T>(
        &mut self,
        max: usize,
        what: &'static str,
        mut f: impl FnMut(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Vec<T>, DecodeError> {
        let n = self.count(max, what)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(f(self)?);
        }
        Ok(out)
    }

    pub fn opt<T>(
        &mut self,
        what: &'static str,
        f: impl FnOnce(&mut Self) -> Result<T, DecodeError>,
    ) -> Result<Option<T>, DecodeError> {
        match self.u8(what)? {
            0 => Ok(None),
            1 => f(self).map(Some),
            t => Err(DecodeError {
                offset: self.pos - 1,
                what,
                reason: Reason::BadTag(t),
            }),
        }
    }

    pub fn bad_tag(&self, what: &'static str, tag: u8) -> DecodeError {
        DecodeError {
            offset: self.pos.saturating_sub(1),
            what,
            reason: Reason::BadTag(tag),
        }
    }

    pub fn invalid(&self, what: &'static str) -> DecodeError {
        self.err(what, Reason::Invalid)
    }

    pub fn unsorted(&self, what: &'static str) -> DecodeError {
        self.err(what, Reason::Unsorted)
    }

    /// Succeeds only when every byte was consumed.
    pub fn finish(self) -> Result<(), DecodeError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(self.err("payload", Reason::Trailing))
        }
    }
}

/// True when `items` is strictly ascending under `key` (canonical sorted
/// collections admit no duplicates).
pub fn strictly_ascending<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> bool {
    items.windows(2).all(|w| key(&w[0]) < key(&w[1]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_every_primitive_and_refuses_trailing_bytes() {
        let mut w = Writer::new();
        w.u8(7)
            .bool(true)
            .u16(0xBEEF)
            .u32(1)
            .u64(u64::MAX)
            .u128(u128::MAX / 3)
            .i32(-5)
            .i64(i64::MIN)
            .i128(-170_141_183_460_469_231_731_687_303_715_884_105_727)
            .fixed(&[9; 4])
            .bytes(b"abc")
            .str("héllo")
            .opt(None::<&u8>, |w, v| {
                w.u8(*v);
            })
            .opt(Some(&3u8), |w, v| {
                w.u8(*v);
            })
            .list(&[1u16, 2, 3], |w, v| {
                w.u16(*v);
            });
        let bytes = w.finish().unwrap();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.u8("a").unwrap(), 7);
        assert!(r.bool("b").unwrap());
        assert_eq!(r.u16("c").unwrap(), 0xBEEF);
        assert_eq!(r.u32("d").unwrap(), 1);
        assert_eq!(r.u64("e").unwrap(), u64::MAX);
        assert_eq!(r.u128("f").unwrap(), u128::MAX / 3);
        assert_eq!(r.i32("g").unwrap(), -5);
        assert_eq!(r.i64("h").unwrap(), i64::MIN);
        assert_eq!(
            r.i128("i").unwrap(),
            -170_141_183_460_469_231_731_687_303_715_884_105_727
        );
        assert_eq!(r.fixed::<4>("j").unwrap(), [9; 4]);
        assert_eq!(r.bytes(8, "k").unwrap(), b"abc");
        assert_eq!(r.str(8, "l").unwrap(), "héllo");
        assert_eq!(r.opt("m", |r| r.u8("m")).unwrap(), None);
        assert_eq!(r.opt("n", |r| r.u8("n")).unwrap(), Some(3));
        assert_eq!(r.list(8, "o", |r| r.u16("o")).unwrap(), vec![1, 2, 3]);
        r.finish().unwrap();

        let mut r = Reader::new(&bytes);
        r.u8("a").unwrap();
        assert_eq!(r.finish().unwrap_err().reason, Reason::Trailing);
    }

    #[test]
    fn bounds_are_checked_before_allocation() {
        // A count of 4 billion with two bytes remaining is refused as truncated,
        // not allocated.
        let bytes = [0xFF, 0xFF, 0xFF, 0xFF, 0, 0];
        let mut r = Reader::new(&bytes);
        assert_eq!(
            r.count(usize::MAX, "n").unwrap_err().reason,
            Reason::Truncated
        );
        let mut r = Reader::new(&bytes);
        assert!(matches!(
            r.count(10, "n").unwrap_err().reason,
            Reason::TooLong { max: 10, .. }
        ));
        // A byte string longer than its bound is refused.
        let mut w = Writer::new();
        w.bytes(&[0u8; 100]);
        let b = w.finish().unwrap();
        assert!(matches!(
            Reader::new(&b).bytes(64, "s").unwrap_err().reason,
            Reason::TooLong { .. }
        ));
        // Bad UTF-8 and bad option tags are refused.
        let mut w = Writer::new();
        w.bytes(&[0xFF, 0xFE]);
        let b = w.finish().unwrap();
        assert_eq!(
            Reader::new(&b).str(8, "s").unwrap_err().reason,
            Reason::BadUtf8
        );
        assert_eq!(
            Reader::new(&[2])
                .opt("o", |r| r.u8("o"))
                .unwrap_err()
                .reason,
            Reason::BadTag(2)
        );
    }

    #[test]
    fn strictly_ascending_rejects_duplicates() {
        assert!(strictly_ascending(&[1, 2, 3], |x| *x));
        assert!(!strictly_ascending(&[1, 1], |x| *x));
        assert!(!strictly_ascending(&[2, 1], |x| *x));
        assert!(strictly_ascending::<u8, u8>(&[], |x| *x));
    }
}
