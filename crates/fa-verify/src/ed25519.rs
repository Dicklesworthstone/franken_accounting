//! Ed25519 signature verification (RFC 8032 §5.1), written from the
//! specification for this crate alone.
//!
//! Checkpoints are signed with Ed25519 over domain-separated transcripts
//! (plan §13.2), and the verifier must be auditable in isolation (§13.3),
//! so it carries its own curve arithmetic instead of linking the producer's
//! signer: a shared arithmetic bug would make a forged signature and its
//! check agree.
//!
//! Only public data passes through here (keys, messages, signatures), so
//! the arithmetic is plain and variable-time: field elements are sixteen
//! signed 16-bit limbs, points are extended homogeneous coordinates with
//! the complete addition law of §5.1.4, and scalar multiplication is
//! double-and-add. Every constant is derived from its definition in §5.1
//! when first used — `d = −121665/121666`, `√−1 = 2^((p−1)/4)`, the base
//! point as the point with `y = 4/5` and even `x`, and the group order
//! `L = 2^252 + 27742317777372353535851937790883648493` — rather than
//! typed as opaque limbs.
//!
//! [`verify`] follows §5.1.7: R decodes as a point, S as an integer below
//! L, A as a point (every decoding failure is a refusal), and the group
//! equation checked is the cofactored `[8][S]B = [8]R + [8][k]A`. It is
//! stricter than the bare equation in one way (ruling 3392): A and R must
//! not be small-order points. A small-order A (the identity among them)
//! satisfies the equation for every message under a small-order R, and no
//! validly generated key or honest R is one; [`check_public_key`] is the
//! same boundary for admitting a trusted key. The tests pin RFC 8032 §7.1's
//! vectors, typed from the RFC text.

use std::sync::OnceLock;

use crate::sha512::sha512;

/// Why a signature does not verify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureError {
    /// The public key is not the encoding of a curve point.
    PublicKey,
    /// The public key is a small-order (torsion) point: no validly
    /// generated secret corresponds to it, and with a small-order R it
    /// satisfies the equation for every message.
    SmallOrderKey,
    /// The signature's first half (R) is not the encoding of a curve point.
    R,
    /// The signature's R is a small-order (torsion) point; no honest signer
    /// produces one.
    SmallOrderR,
    /// The signature's second half (S) is not an integer below L.
    S,
    /// The decodings succeed but the group equation does not hold.
    Equation,
}

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::PublicKey => "the public key does not decode to a curve point",
            Self::SmallOrderKey => {
                "the public key is a small-order point, which no validly generated key is"
            }
            Self::R => "the signature's R does not decode to a curve point",
            Self::SmallOrderR => "the signature's R is a small-order point",
            Self::S => "the signature's S is not below the group order",
            Self::Equation => "the signature does not satisfy [8][S]B = [8]R + [8][k]A",
        })
    }
}

// ---- GF(2^255 - 19) ---------------------------------------------------------

/// `Σ limb[i] · 2^(16 i)`; limbs may leave `[0, 2^16)` between carries.
#[derive(Clone, Copy, Debug)]
struct Fe([i64; 16]);

/// p = 2^255 − 19 in 16-bit limbs.
const P_LIMBS: [i64; 16] = [
    0xffed, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
    0xffff, 0xffff, 0xffff, 0x7fff,
];

/// Exponents, little-endian: p − 2 (inversion), (p − 5)/8 (the square-root
/// candidate of §5.1.3), (p − 1)/4 (for √−1).
const P_MINUS_2: [u8; 32] = le_all_ones(0xeb, 0x7f);
const P_MINUS_5_OVER_8: [u8; 32] = le_all_ones(0xfd, 0x0f);
const P_MINUS_1_OVER_4: [u8; 32] = le_all_ones(0xfb, 0x1f);

/// `low ‖ 0xff × 30 ‖ high`, little-endian.
const fn le_all_ones(low: u8, high: u8) -> [u8; 32] {
    let mut b = [0xff; 32];
    b[0] = low;
    b[31] = high;
    b
}

impl Fe {
    const ZERO: Fe = Fe([0; 16]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

    fn from_u32(v: u32) -> Fe {
        let mut l = [0i64; 16];
        l[0] = i64::from(v & 0xffff);
        l[1] = i64::from(v >> 16);
        Fe(l)
    }

    /// One carry pass: each limb keeps its low 16 bits (floor division, so
    /// negative limbs borrow), and the carry out of limb 15 re-enters limb 0
    /// times 38, since 2^256 ≡ 38 (mod p).
    fn carry(&mut self) {
        for i in 0..16 {
            let c = self.0[i] >> 16;
            self.0[i] -= c * 65536;
            if i < 15 {
                self.0[i + 1] += c;
            } else {
                self.0[0] += 38 * c;
            }
        }
    }

    fn add(&self, b: &Fe) -> Fe {
        let mut o = [0i64; 16];
        for (i, x) in o.iter_mut().enumerate() {
            *x = self.0[i] + b.0[i];
        }
        Fe(o)
    }

    fn sub(&self, b: &Fe) -> Fe {
        let mut o = [0i64; 16];
        for (i, x) in o.iter_mut().enumerate() {
            *x = self.0[i] - b.0[i];
        }
        Fe(o)
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(&self, b: &Fe) -> Fe {
        let mut t = [0i64; 31];
        for i in 0..16 {
            for j in 0..16 {
                t[i + j] += self.0[i] * b.0[j];
            }
        }
        // Limb 16 + i weighs 2^256 · 2^(16 i) ≡ 38 · 2^(16 i).
        for i in 0..15 {
            t[i] += 38 * t[i + 16];
        }
        let mut o = Fe([0; 16]);
        o.0.copy_from_slice(&t[..16]);
        o.carry();
        o.carry();
        o
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    /// `self^e`, square-and-multiply over the bits of `e` (little-endian).
    fn pow(&self, e: &[u8; 32]) -> Fe {
        let mut r = Fe::ONE;
        for bit in (0..256).rev() {
            r = r.square();
            if (e[bit / 8] >> (bit % 8)) & 1 == 1 {
                r = r.mul(self);
            }
        }
        r
    }

    fn invert(&self) -> Fe {
        self.pow(&P_MINUS_2)
    }

    /// The canonical little-endian encoding of the value in `[0, p)`.
    fn to_bytes(self) -> [u8; 32] {
        let mut t = self;
        // Carry until every limb is in [0, 2^16): the value is then in
        // [0, 2^256). A negative value wraps by 2^256 − 38 = 2p per pass,
        // which keeps it congruent mod p.
        loop {
            t.carry();
            if t.0.iter().all(|l| (0..65536).contains(l)) {
                break;
            }
        }
        // 2^256 < 3p: at most two subtractions of p.
        for _ in 0..2 {
            let mut m = [0i64; 16];
            let mut borrow = 0i64;
            for i in 0..16 {
                let v = t.0[i] - P_LIMBS[i] - borrow;
                borrow = i64::from(v < 0);
                m[i] = v + borrow * 65536;
            }
            if borrow == 0 {
                t.0 = m;
            }
        }
        let mut out = [0u8; 32];
        for i in 0..16 {
            out[2 * i] = (t.0[i] & 0xff) as u8;
            out[2 * i + 1] = (t.0[i] >> 8) as u8;
        }
        out
    }

    /// A canonical encoding (value below p) or `None`. The caller clears
    /// any bit it uses for something else.
    fn from_canonical_bytes(b: &[u8; 32]) -> Option<Fe> {
        let mut l = [0i64; 16];
        for (i, x) in l.iter_mut().enumerate() {
            *x = i64::from(b[2 * i]) | (i64::from(b[2 * i + 1]) << 8);
        }
        let fe = Fe(l);
        (fe.to_bytes() == *b).then_some(fe)
    }

    fn equals(&self, b: &Fe) -> bool {
        self.to_bytes() == b.to_bytes()
    }

    fn is_zero(&self) -> bool {
        self.to_bytes() == [0; 32]
    }

    /// The least significant bit of the canonical value (§5.1.2's "x is
    /// negative").
    fn is_odd(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }
}

// ---- edwards25519 -----------------------------------------------------------

/// Extended homogeneous coordinates: x = X/Z, y = Y/Z, x·y = T/Z.
#[derive(Clone, Copy, Debug)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

struct Curve {
    /// 2·d, the constant of the addition law.
    d2: Fe,
    d: Fe,
    sqrt_m1: Fe,
    base: Point,
}

fn curve() -> &'static Curve {
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| {
        // §5.1: d = −121665 / 121666.
        let d = Fe::from_u32(121_665)
            .neg()
            .mul(&Fe::from_u32(121_666).invert());
        let sqrt_m1 = Fe::from_u32(2).pow(&P_MINUS_1_OVER_4);
        let partial = Curve {
            d2: d.add(&d),
            d,
            sqrt_m1,
            base: Point::IDENTITY,
        };
        // §5.1: B is the point with y = 4/5 and x positive (even), so its
        // encoding is y's with the sign bit clear.
        let y = Fe::from_u32(4).mul(&Fe::from_u32(5).invert());
        let base = Point::decode_with(&partial, &y.to_bytes()).expect("4/5 is a curve y");
        Curve { base, ..partial }
    })
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    /// §5.1.4's complete addition law for a = −1.
    fn add(&self, q: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&q.y.sub(&q.x));
        let b = self.y.add(&self.x).mul(&q.y.add(&q.x));
        let c = self.t.mul(&curve().d2).mul(&q.t);
        let d = self.z.add(&self.z).mul(&q.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// `[k]P` for a little-endian 256-bit `k`, most significant bit first.
    fn mul(&self, k: &[u8; 32]) -> Point {
        let mut r = Point::IDENTITY;
        for bit in (0..256).rev() {
            r = r.add(&r);
            if (k[bit / 8] >> (bit % 8)) & 1 == 1 {
                r = r.add(self);
            }
        }
        r
    }

    fn is_identity(&self) -> bool {
        self.x.is_zero() && self.y.equals(&self.z)
    }

    /// Whether `[8]self` is the identity: the eight torsion points,
    /// including the identity itself.
    fn has_small_order(&self) -> bool {
        let mut p = *self;
        for _ in 0..3 {
            p = p.add(&p);
        }
        p.is_identity()
    }

    #[cfg(test)]
    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let mut out = self.y.mul(&zi).to_bytes();
        out[31] |= u8::from(self.x.mul(&zi).is_odd()) << 7;
        out
    }

    fn decode(b: &[u8; 32]) -> Option<Point> {
        Self::decode_with(curve(), b)
    }

    /// §5.1.3, with the curve constants passed in (the base point is
    /// itself decoded while they are being built).
    fn decode_with(c: &Curve, b: &[u8; 32]) -> Option<Point> {
        let x0 = b[31] >> 7;
        let mut yb = *b;
        yb[31] &= 0x7f;
        let y = Fe::from_canonical_bytes(&yb)?;
        let y2 = y.square();
        let u = y2.sub(&Fe::ONE);
        let v = c.d.mul(&y2).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow(&P_MINUS_5_OVER_8));
        let vx2 = v.mul(&x.square());
        if !vx2.equals(&u) {
            if !vx2.equals(&u.neg()) {
                return None;
            }
            x = x.mul(&c.sqrt_m1);
        }
        if x.is_zero() && x0 == 1 {
            return None;
        }
        if u8::from(x.is_odd()) != x0 {
            x = x.neg();
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }
}

// ---- scalars mod L ----------------------------------------------------------

/// L = 2^252 + 27742317777372353535851937790883648493, as four
/// little-endian 64-bit limbs.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

fn limbs(b: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, chunk) in b.as_chunks::<8>().0.iter().enumerate() {
        out[i] = u64::from_le_bytes(*chunk);
    }
    out
}

/// `a − b` and whether it borrowed (that is, whether `a < b`).
fn sub_borrow(a: &[u64; 4], b: &[u64; 4]) -> ([u64; 4], bool) {
    let mut out = [0u64; 4];
    let mut borrow = false;
    for i in 0..4 {
        let (v, o1) = a[i].overflowing_sub(b[i]);
        let (v, o2) = v.overflowing_sub(u64::from(borrow));
        out[i] = v;
        borrow = o1 || o2;
    }
    (out, borrow)
}

fn ge(a: &[u64; 4], b: &[u64; 4]) -> bool {
    !sub_borrow(a, b).1
}

/// A 512-bit little-endian integer mod L, by binary long division (plain
/// and obviously correct; the remainder stays below 2L < 2^254).
fn reduce_wide(x: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        let carry_in = u64::from((x[bit / 8] >> (bit % 8)) & 1);
        for i in (1..4).rev() {
            r[i] = (r[i] << 1) | (r[i - 1] >> 63);
        }
        r[0] = (r[0] << 1) | carry_in;
        let (d, borrow) = sub_borrow(&r, &L);
        if !borrow {
            r = d;
        }
    }
    let mut out = [0u8; 32];
    for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(r) {
        *chunk = w.to_le_bytes();
    }
    out
}

// ---- verification -----------------------------------------------------------

/// Whether `public_key` may be trusted as an Ed25519 key at all: a canonical
/// encoding of a curve point that is not of small order. A small-order key
/// (the identity among them) satisfies the cofactored equation for every
/// message under a small-order R, so no claim may rest on one (ruling 3392).
pub fn check_public_key(public_key: &[u8; 32]) -> Result<(), SignatureError> {
    let a = Point::decode(public_key).ok_or(SignatureError::PublicKey)?;
    if a.has_small_order() {
        return Err(SignatureError::SmallOrderKey);
    }
    Ok(())
}

/// RFC 8032 §5.1.7 for pure Ed25519 (no context, no prehash), strict: the
/// key and R must also not be small-order points.
pub fn verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> Result<(), SignatureError> {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let a = Point::decode(public_key).ok_or(SignatureError::PublicKey)?;
    if a.has_small_order() {
        return Err(SignatureError::SmallOrderKey);
    }
    let r = Point::decode(&r_bytes).ok_or(SignatureError::R)?;
    if r.has_small_order() {
        return Err(SignatureError::SmallOrderR);
    }
    if ge(&limbs(&s_bytes), &L) {
        return Err(SignatureError::S);
    }
    let k = reduce_wide(&sha512(&[&r_bytes, public_key, message]));
    // [S]B − R − [k]A, then the cofactor 8 as three doublings.
    let mut check = curve()
        .base
        .mul(&s_bytes)
        .add(&r.neg())
        .add(&a.mul(&k).neg());
    for _ in 0..3 {
        check = check.add(&check);
    }
    if check.is_identity() {
        Ok(())
    } else {
        Err(SignatureError::Equation)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn unhex<const N: usize>(s: &str) -> [u8; N] {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        let v: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        v.try_into().unwrap()
    }

    /// RFC 8032 §7.1: (public key, message, signature), typed from the RFC.
    /// TEST 1, TEST 2, TEST 3 and TEST SHA(abc). (The secret keys are the
    /// signer's concern; fa-notary's tests use them.)
    pub(crate) const RFC8032: [(&str, &str, &str); 4] = [
        (
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155\
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589\
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    fn message(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn rfc8032_vectors_verify() {
        for (pk, msg, sig) in RFC8032 {
            let msg: String = msg.chars().filter(|c| !c.is_whitespace()).collect();
            assert_eq!(
                verify(&unhex(pk), &message(&msg), &unhex(sig)),
                Ok(()),
                "{pk}"
            );
        }
    }

    /// Planted negatives on every vector: one flipped bit, at sampled
    /// positions covering each decoding step, in the signature or the key,
    /// and an altered message, are each refused.
    #[test]
    fn single_bit_forgeries_are_refused() {
        for (pk, msg, sig) in RFC8032 {
            let msg: String = msg.chars().filter(|c| !c.is_whitespace()).collect();
            let (pk, msg, sig): ([u8; 32], Vec<u8>, [u8; 64]) =
                (unhex(pk), message(&msg), unhex(sig));
            // R's low, middle and top y bits and its sign bit; S's low,
            // middle and top bits (the top ones push S past L); the key's
            // the same. Every bit is covered by the RFC's own argument;
            // these exercise each decoding step and the equation.
            for i in [
                0, 1, 7, 8, 100, 200, 254, 255, 256, 257, 300, 400, 500, 508, 509, 511,
            ] {
                let mut s = sig;
                s[i / 8] ^= 1 << (i % 8);
                assert!(verify(&pk, &msg, &s).is_err(), "signature bit {i}");
            }
            for i in [0, 1, 100, 200, 254, 255] {
                let mut k = pk;
                k[i / 8] ^= 1 << (i % 8);
                assert!(verify(&k, &msg, &sig).is_err(), "key bit {i}");
            }
            let mut m = msg.clone();
            m.push(0);
            assert_eq!(verify(&pk, &m, &sig), Err(SignatureError::Equation));
            if !msg.is_empty() {
                let mut m = msg.clone();
                m[0] ^= 0x80;
                assert_eq!(verify(&pk, &m, &sig), Err(SignatureError::Equation));
            }
        }
    }

    /// The eight torsion points, found from the math rather than typed in:
    /// for a point P, [L]P is P's torsion component (L·P_main = O, and L is
    /// odd so the order is kept); one of order 8 generates the whole
    /// subgroup.
    pub(crate) fn torsion_encodings() -> Vec<[u8; 32]> {
        let mut l_bytes = [0u8; 32];
        for (chunk, w) in l_bytes.as_chunks_mut::<8>().0.iter_mut().zip(L) {
            *chunk = w.to_le_bytes();
        }
        for y in 2u32.. {
            let Some(p) = Point::decode(&Fe::from_u32(y).to_bytes()) else {
                continue;
            };
            let t = p.mul(&l_bytes);
            let mut t4 = t;
            for _ in 0..2 {
                t4 = t4.add(&t4);
            }
            if t4.is_identity() {
                continue; // order divides 4: not a generator
            }
            let mut out = Vec::new();
            let mut acc = Point::IDENTITY;
            for _ in 0..8 {
                out.push(acc.encode());
                acc = acc.add(&t);
            }
            assert!(acc.is_identity(), "[8]T is the identity");
            out.sort_unstable();
            out.dedup();
            return out;
        }
        Vec::new() // never reached: the callers assert eight encodings
    }

    /// Ruling 3392 (WhiteCreek 3391): a small-order key satisfies the
    /// cofactored equation for every message under a small-order R. The
    /// exact candidate — identity key, R = identity, S = 0 — is refused for
    /// two distinct messages with the typed error, every torsion encoding is
    /// refused as a key and as R, and generated keys still pass.
    #[test]
    fn small_order_keys_and_r_are_refused() {
        let mut identity = [0u8; 32];
        identity[0] = 1;
        let mut candidate = [0u8; 64];
        candidate[..32].copy_from_slice(&identity);
        for message in [
            &b"checkpoint body one"[..],
            &b"a different checkpoint body"[..],
        ] {
            assert_eq!(
                verify(&identity, message, &candidate),
                Err(SignatureError::SmallOrderKey)
            );
        }
        let torsion = torsion_encodings();
        assert_eq!(torsion.len(), 8, "the eight torsion points");
        assert!(torsion.contains(&identity));
        let (pk, _, sig) = RFC8032[0];
        let (pk, sig): ([u8; 32], [u8; 64]) = (unhex(pk), unhex(sig));
        for t in &torsion {
            assert_eq!(check_public_key(t), Err(SignatureError::SmallOrderKey));
            let mut s = sig;
            s[..32].copy_from_slice(t);
            assert_eq!(verify(&pk, b"", &s), Err(SignatureError::SmallOrderR));
            let mut forged = [0u8; 64];
            forged[..32].copy_from_slice(t);
            assert_eq!(
                verify(t, b"any", &forged),
                Err(SignatureError::SmallOrderKey)
            );
        }
        for (pk, _, _) in RFC8032 {
            assert_eq!(check_public_key(&unhex(pk)), Ok(()), "{pk}");
        }
        assert_eq!(verify(&pk, b"", &sig), Ok(()), "positive control");
    }

    /// S ≥ L is refused before any curve work, even when S − L would
    /// verify (signature malleability, §5.1.7 step 1).
    #[test]
    fn a_non_reduced_s_is_refused() {
        let (pk, _, sig) = RFC8032[0];
        let (pk, sig): ([u8; 32], [u8; 64]) = (unhex(pk), unhex(sig));
        let mut s = limbs(sig[32..].try_into().unwrap());
        // S + L, still below 2^256.
        let mut carry = false;
        for (i, l) in L.iter().enumerate() {
            let (v, o1) = s[i].overflowing_add(*l);
            let (v, o2) = v.overflowing_add(u64::from(carry));
            s[i] = v;
            carry = o1 || o2;
        }
        assert!(!carry);
        let mut forged = sig;
        for (chunk, w) in forged[32..].as_chunks_mut::<8>().0.iter_mut().zip(s) {
            *chunk = w.to_le_bytes();
        }
        assert_eq!(verify(&pk, b"", &forged), Err(SignatureError::S));
    }

    /// The constants derived from §5.1's definitions encode as expected:
    /// the base point's encoding is y = 4/5 (0x58 0x66 …), and L's limbs
    /// are 2^252 + 27742317777372353535851937790883648493 (checked by
    /// reducing L, L + 1 and 2^512 − 1 against independent identities).
    #[test]
    fn derived_constants() {
        let mut b = [0x66u8; 32];
        b[0] = 0x58;
        assert_eq!(curve().base.encode(), b);
        assert!(curve().sqrt_m1.square().equals(&Fe::ONE.neg()));
        // −121665 = d · 121666.
        assert!(
            curve()
                .d
                .mul(&Fe::from_u32(121_666))
                .equals(&Fe::from_u32(121_665).neg())
        );
        // [L]B is the identity and [L−1]B = −B.
        let mut l_bytes = [0u8; 32];
        for (chunk, w) in l_bytes.as_chunks_mut::<8>().0.iter_mut().zip(L) {
            *chunk = w.to_le_bytes();
        }
        assert!(curve().base.mul(&l_bytes).is_identity());
        let mut l_minus_1 = l_bytes;
        l_minus_1[0] -= 1;
        assert_eq!(
            curve().base.mul(&l_minus_1).encode(),
            curve().base.neg().encode()
        );
        // x mod L for x = L, L + 5, and a 64-byte value.
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&l_bytes);
        assert_eq!(reduce_wide(&wide), [0; 32]);
        wide[0] += 5;
        let mut five = [0u8; 32];
        five[0] = 5;
        assert_eq!(reduce_wide(&wide), five);
    }

    /// The field: canonical encodings round-trip and p itself, p + 1 and
    /// 2^255 − 1 are not canonical.
    #[test]
    fn field_encoding_is_canonical() {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert!(Fe::from_canonical_bytes(&p).is_none());
        let mut p1 = p;
        p1[0] = 0xee;
        assert!(Fe::from_canonical_bytes(&p1).is_none());
        let mut top = [0xffu8; 32];
        top[31] = 0x7f;
        assert!(Fe::from_canonical_bytes(&top).is_none());
        let mut pm1 = p;
        pm1[0] = 0xec;
        assert_eq!(Fe::from_canonical_bytes(&pm1).unwrap().to_bytes(), pm1);
        // (p − 1) + 1 = 0, and its negation is 1.
        let pm1 = Fe::from_canonical_bytes(&pm1).unwrap();
        assert!(pm1.add(&Fe::ONE).is_zero());
        assert!(pm1.neg().equals(&Fe::ONE));
    }
}
