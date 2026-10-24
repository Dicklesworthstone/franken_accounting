//! Ed25519 signing (RFC 8032 §5.1.5–§5.1.6), the interim signer.
//!
//! Interim (Appendix H R-SIGN): fgdb-crypto ships no signature scheme at the
//! pinned revision (upstream request: frankengraphdb#3). When it does,
//! [`super::CheckpointSigner`] is implemented over it and this module goes.
//!
//! Secret-dependent work — the fixed-base multiplications `[s]B` and
//! `[r]B` and the scalar arithmetic `S = r + k·s mod L` — is constant-time
//! by construction: a fixed-base table of `j·16^i·B` read by mask-select
//! over all sixteen entries (no secret index), the complete addition law
//! (no secret branch), and reduction mod L by a fixed 512-step long
//! division with masked subtraction. Every mask passes `black_box`, so the
//! optimizer cannot prove it boolean and turn a select back into a branch
//! (a best-effort barrier, not a guarantee). A dudect-style harness
//! (`crate::ct_harness`, bead fa-cs80) times `mul_base`, the reduction and
//! `sign` on fixed against random secrets; each run is `statistical`
//! evidence about one build on one host. The claim class stays
//! `bounded_model`, never `invariant`.
//!
//! Field elements are five 51-bit limbs with 128-bit products — a
//! different representation from fa-verify's sixteen 16-bit limbs, so the
//! signer↔verifier differential compares independent arithmetic.

use std::hint::black_box;
use std::sync::OnceLock;

use fgdb_crypto::zeroize::{Secret, scrub_slice, scrub_words};

use super::sha512::sha512;

const MASK51: u64 = (1 << 51) - 1;

// ---- GF(2^255 − 19) ---------------------------------------------------------

/// `Σ limb[i] · 2^(51 i)`, limbs kept below about 2^52 between operations.
#[derive(Clone, Copy)]
struct Fe([u64; 5]);

/// p − 2, little-endian (inversion by Fermat).
const P_MINUS_2: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xeb;
    b[31] = 0x7f;
    b
};
/// (p − 5)/8 and (p − 1)/4, for the base point's square root.
const P_MINUS_5_OVER_8: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xfd;
    b[31] = 0x0f;
    b
};
const P_MINUS_1_OVER_4: [u8; 32] = {
    let mut b = [0xff; 32];
    b[0] = 0xfb;
    b[31] = 0x1f;
    b
};

impl Fe {
    const ZERO: Fe = Fe([0; 5]);
    const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    fn small(v: u64) -> Fe {
        Fe([v, 0, 0, 0, 0])
    }

    /// One carry chain: limbs back below 2^51, the overflow of limb 4
    /// re-entering limb 0 times 19 (2^255 ≡ 19).
    fn carried(mut l: [u64; 5]) -> Fe {
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK51;
        }
        let c = l[4] >> 51;
        l[4] &= MASK51;
        l[0] += 19 * c;
        Fe(l)
    }

    fn add(&self, b: &Fe) -> Fe {
        let mut l = [0u64; 5];
        for (i, x) in l.iter_mut().enumerate() {
            *x = self.0[i] + b.0[i];
        }
        Fe::carried(l)
    }

    /// `self − b + 4p`, so no limb underflows for inputs below 2^53.
    fn sub(&self, b: &Fe) -> Fe {
        const FOUR_P: [u64; 5] = [
            4 * ((1 << 51) - 19),
            4 * MASK51,
            4 * MASK51,
            4 * MASK51,
            4 * MASK51,
        ];
        let mut l = [0u64; 5];
        for (i, x) in l.iter_mut().enumerate() {
            *x = self.0[i] + FOUR_P[i] - b.0[i];
        }
        Fe::carried(l)
    }

    fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    fn mul(&self, b: &Fe) -> Fe {
        let [a0, a1, a2, a3, a4] = self.0;
        let [b0, b1, b2, b3, b4] = b.0;
        let m = |x: u64, y: u64| u128::from(x) * u128::from(y);
        let (b1t, b2t, b3t, b4t) = (19 * b1, 19 * b2, 19 * b3, 19 * b4);
        let c0 = m(a0, b0) + m(a1, b4t) + m(a2, b3t) + m(a3, b2t) + m(a4, b1t);
        let c1 = m(a0, b1) + m(a1, b0) + m(a2, b4t) + m(a3, b3t) + m(a4, b2t);
        let c2 = m(a0, b2) + m(a1, b1) + m(a2, b0) + m(a3, b4t) + m(a4, b3t);
        let c3 = m(a0, b3) + m(a1, b2) + m(a2, b1) + m(a3, b0) + m(a4, b4t);
        let c4 = m(a0, b4) + m(a1, b3) + m(a2, b2) + m(a3, b1) + m(a4, b0);
        let c1 = c1 + (c0 >> 51);
        let c2 = c2 + (c1 >> 51);
        let c3 = c3 + (c2 >> 51);
        let c4 = c4 + (c3 >> 51);
        let low = |c: u128| (c as u64) & MASK51;
        Fe::carried([
            low(c0) + 19 * ((c4 >> 51) as u64),
            low(c1),
            low(c2),
            low(c3),
            low(c4),
        ])
    }

    fn square(&self) -> Fe {
        self.mul(self)
    }

    /// `self^e` for a public, fixed exponent.
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

    /// The canonical encoding, without a value-dependent branch: carry
    /// fully, then subtract p exactly when the value is at least p (the
    /// carry out of `value + 19` past bit 255 says so).
    fn to_bytes(self) -> [u8; 32] {
        let mut l = Fe::carried(Fe::carried(Fe::carried(self.0).0).0).0;
        let mut q = (l[0] + 19) >> 51;
        for limb in &l[1..] {
            q = (limb + q) >> 51;
        }
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK51;
        }
        l[4] &= MASK51;
        let mut out = [0u8; 32];
        let mut acc: u128 = 0;
        let mut bits = 0;
        let mut at = 0;
        for limb in l {
            acc |= u128::from(limb) << bits;
            bits += 51;
            while bits >= 8 {
                out[at] = acc as u8;
                acc >>= 8;
                bits -= 8;
                at += 1;
            }
        }
        out[at] = acc as u8;
        out
    }

    /// A canonical encoding (value below p, bit 255 clear) or `None`.
    fn from_canonical_bytes(b: &[u8; 32]) -> Option<Fe> {
        let mut w = [0u64; 4];
        for (word, chunk) in w.iter_mut().zip(b.as_chunks::<8>().0) {
            *word = u64::from_le_bytes(*chunk);
        }
        let fe = Fe([
            w[0] & MASK51,
            ((w[0] >> 51) | (w[1] << 13)) & MASK51,
            ((w[1] >> 38) | (w[2] << 26)) & MASK51,
            ((w[2] >> 25) | (w[3] << 39)) & MASK51,
            (w[3] >> 12) & MASK51,
        ]);
        (fe.to_bytes() == *b).then_some(fe)
    }

    /// `a` where `mask` is zero, `b` where it is all ones.
    fn select(a: &Fe, b: &Fe, mask: u64) -> Fe {
        let mut l = [0u64; 5];
        for (i, x) in l.iter_mut().enumerate() {
            *x = (a.0[i] & !mask) | (b.0[i] & mask);
        }
        Fe(l)
    }
}

// ---- edwards25519 -----------------------------------------------------------

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

const IDENTITY: Point = Point {
    x: Fe::ZERO,
    y: Fe::ONE,
    z: Fe::ONE,
    t: Fe::ZERO,
};

impl Point {
    /// RFC 8032 §5.1.4's complete addition law (a = −1): no branch, valid
    /// for every pair of points including equal ones and the identity.
    fn add(&self, q: &Point, d2: &Fe) -> Point {
        let a = self.y.sub(&self.x).mul(&q.y.sub(&q.x));
        let b = self.y.add(&self.x).mul(&q.y.add(&q.x));
        let c = self.t.mul(d2).mul(&q.t);
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

    fn select(a: &Point, b: &Point, mask: u64) -> Point {
        Point {
            x: Fe::select(&a.x, &b.x, mask),
            y: Fe::select(&a.y, &b.y, mask),
            z: Fe::select(&a.z, &b.z, mask),
            t: Fe::select(&a.t, &b.t, mask),
        }
    }

    /// §5.1.2: y with the low bit of x in bit 255.
    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let mut out = self.y.mul(&zi).to_bytes();
        out[31] |= (self.x.mul(&zi).to_bytes()[0] & 1) << 7;
        out
    }
}

/// The curve constants and the table `TABLE[i][j] = j · 16^i · B`.
struct Tables {
    d: Fe,
    d2: Fe,
    sqrt_m1: Fe,
    table: Vec<[Point; 16]>,
}

/// RFC 8032 §5.1.3: the point with this y whose x has low bit `x0`, or
/// `None` when no x exists. Public data only.
fn recover(d: &Fe, sqrt_m1: &Fe, y: Fe, x0: u8) -> Option<Point> {
    let y2 = y.square();
    let u = y2.sub(&Fe::ONE);
    let v = d.mul(&y2).add(&Fe::ONE);
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow(&P_MINUS_5_OVER_8));
    let vx2 = v.mul(&x.square()).to_bytes();
    if vx2 != u.to_bytes() {
        if vx2 != u.neg().to_bytes() {
            return None;
        }
        x = x.mul(sqrt_m1);
    }
    let low = x.to_bytes()[0] & 1;
    if x.to_bytes() == [0; 32] && x0 == 1 {
        return None;
    }
    if low != x0 {
        x = x.neg();
    }
    Some(Point {
        x,
        y,
        z: Fe::ONE,
        t: x.mul(&y),
    })
}

fn tables() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        // §5.1: d = −121665/121666; B = (x, 4/5) with x even. Public data,
        // computed once.
        let d = Fe::small(121_665).neg().mul(&Fe::small(121_666).invert());
        let d2 = d.add(&d);
        let sqrt_m1 = Fe::small(2).pow(&P_MINUS_1_OVER_4);
        let y = Fe::small(4).mul(&Fe::small(5).invert());
        let mut step = recover(&d, &sqrt_m1, y, 0).expect("4/5 is the base point's y");
        let mut table = Vec::with_capacity(64);
        for _ in 0..64 {
            let mut row = [IDENTITY; 16];
            for j in 1..16 {
                row[j] = row[j - 1].add(&step, &d2);
            }
            table.push(row);
            for _ in 0..4 {
                step = step.add(&step, &d2);
            }
        }
        Tables {
            d,
            d2,
            sqrt_m1,
            table,
        }
    })
}

/// `[k]B` for a little-endian 256-bit `k`: sixty-four 4-bit digits, each
/// selecting its table entry by mask over all sixteen.
fn mul_base(k: &[u8; 32]) -> Point {
    let t = tables();
    let mut acc = IDENTITY;
    for (i, row) in t.table.iter().enumerate() {
        let digit = u64::from((k[i / 2] >> (4 * (i % 2))) & 0x0f);
        let mut chosen = IDENTITY;
        for (j, entry) in row.iter().enumerate().skip(1) {
            // All ones iff digit == j, computed without a branch. The
            // barrier hides the mask's provenance, so the optimizer cannot
            // prove it boolean and turn the select back into a branch.
            let diff = digit ^ (j as u64);
            let equal = (diff.wrapping_sub(1) >> 63) & 1;
            let mask = black_box(0u64.wrapping_sub(equal));
            chosen = Point::select(&chosen, entry, mask);
        }
        acc = acc.add(&chosen, &t.d2);
    }
    acc
}

// ---- scalars mod L ----------------------------------------------------------

/// L = 2^252 + 27742317777372353535851937790883648493, little-endian limbs.
const L: [u64; 4] = [
    0x5812_631a_5cf5_d3ed,
    0x14de_f9de_a2f7_9cd6,
    0,
    0x1000_0000_0000_0000,
];

/// `x mod L` for a 512-bit little-endian `x`: 512 fixed steps of
/// shift-in-a-bit and masked conditional subtraction.
fn reduce_512(x: &[u8; 64]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for bit in (0..512).rev() {
        let next = u64::from((x[bit / 8] >> (bit % 8)) & 1);
        r[3] = (r[3] << 1) | (r[2] >> 63);
        r[2] = (r[2] << 1) | (r[1] >> 63);
        r[1] = (r[1] << 1) | (r[0] >> 63);
        r[0] = (r[0] << 1) | next;
        conditional_sub_l(&mut r);
    }
    r
}

/// `r − L` when `r ≥ L`, else `r`, by mask.
fn conditional_sub_l(r: &mut [u64; 4]) {
    let mut d = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (v, o1) = r[i].overflowing_sub(L[i]);
        let (v, o2) = v.overflowing_sub(borrow);
        d[i] = v;
        borrow = u64::from(o1 | o2);
    }
    // borrow = 1 means r < L: keep r. The barrier as in [`mul_base`].
    let keep = black_box(0u64.wrapping_sub(borrow));
    for i in 0..4 {
        r[i] = (r[i] & keep) | (d[i] & !keep);
    }
}

fn limbs(b: &[u8]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for (i, chunk) in b.as_chunks::<8>().0.iter().take(4).enumerate() {
        out[i] = u64::from_le_bytes(*chunk);
    }
    out
}

fn le_bytes(l: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (chunk, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(l) {
        *chunk = w.to_le_bytes();
    }
    out
}

/// `(r + k·s) mod L`; `r`, `k` below L, `s` below 2^255.
fn mul_add_mod_l(r: &[u64; 4], k: &[u64; 4], s: &[u64; 4]) -> [u64; 4] {
    // k·s < 2^508, then + r < 2^509: one 512-bit value, reduced.
    let mut wide = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let v = u128::from(wide[i + j]) + u128::from(k[i]) * u128::from(s[j]) + carry;
            wide[i + j] = v as u64;
            carry = v >> 64;
        }
        wide[i + 4] = carry as u64;
    }
    let mut carry: u128 = 0;
    for (i, w) in wide.iter_mut().enumerate() {
        let v = u128::from(*w) + u128::from(if i < 4 { r[i] } else { 0 }) + carry;
        *w = v as u64;
        carry = v >> 64;
    }
    let mut bytes = [0u8; 64];
    for (chunk, w) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(wide) {
        *chunk = w.to_le_bytes();
    }
    let out = reduce_512(&bytes);
    scrub_slice(&mut bytes);
    scrub_words(&mut wide);
    out
}

// ---- keys and signatures ----------------------------------------------------

/// Why a public key cannot be trusted (ruling 3392).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyError {
    /// Not the canonical encoding of a curve point.
    NotAPoint,
    /// A small-order (torsion) point: no validly generated key is one, and
    /// with a small-order R it satisfies the cofactored equation for every
    /// message.
    SmallOrder,
}

impl core::fmt::Display for KeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::NotAPoint => "the public key is not the canonical encoding of a curve point",
            Self::SmallOrder => {
                "the public key is a small-order point, which no validly generated key is"
            }
        })
    }
}

/// Whether `public_key` may be admitted as a trusted Ed25519 key: a
/// canonical curve point whose order is not small (`[8]A` is not the
/// identity). The producer's own boundary, written apart from fa-verify's.
pub fn check_public_key(public_key: &[u8; 32]) -> Result<(), KeyError> {
    let t = tables();
    let x0 = public_key[31] >> 7;
    let mut yb = *public_key;
    yb[31] &= 0x7f;
    let y = Fe::from_canonical_bytes(&yb).ok_or(KeyError::NotAPoint)?;
    let a = recover(&t.d, &t.sqrt_m1, y, x0).ok_or(KeyError::NotAPoint)?;
    let mut eight = a;
    for _ in 0..3 {
        eight = eight.add(&eight, &t.d2);
    }
    let identity = eight.x.to_bytes() == [0; 32] && eight.y.to_bytes() == eight.z.to_bytes();
    if identity {
        Err(KeyError::SmallOrder)
    } else {
        Ok(())
    }
}

/// An Ed25519 signing key: the clamped secret scalar and the nonce prefix
/// of §5.1.5–§5.1.6, scrubbed on drop, and the public key.
pub struct SigningKey {
    scalar: Secret<32>,
    prefix: Secret<32>,
    public: [u8; 32],
}

impl SigningKey {
    /// §5.1.5 from a 32-byte private key (the seed).
    #[must_use]
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut h = sha512(&[seed]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);
        scrub_slice(&mut h);
        let public = mul_base(&s).encode();
        Self {
            scalar: Secret::new(s),
            prefix: Secret::new(prefix),
            public,
        }
    }

    #[must_use]
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// §5.1.6 for pure Ed25519 (no context, no prehash).
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut rh = sha512(&[self.prefix.expose(), message]);
        let r = reduce_512(&rh);
        scrub_slice(&mut rh);
        let mut r_bytes = le_bytes(&r);
        let big_r = mul_base(&r_bytes).encode();
        scrub_slice(&mut r_bytes);
        let k = reduce_512(&sha512(&[&big_r, &self.public, message]));
        let s = mul_add_mod_l(&r, &k, &limbs(self.scalar.expose()));
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&le_bytes(&s));
        sig
    }
}

impl core::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// The secret-dependent kernels as timing targets for
/// [`crate::ct_harness`], each returning enough of its result that the call
/// cannot be elided, and the leak the harness must catch.
#[cfg(test)]
pub(crate) mod ct_targets {
    use super::*;

    /// `[k]B`'s projective X limbs.
    pub(crate) fn mul_base_x(k: &[u8; 32]) -> [u64; 5] {
        mul_base(k).x.0
    }

    /// `x mod L`.
    pub(crate) fn reduce(x: &[u8; 64]) -> [u64; 4] {
        reduce_512(x)
    }

    /// The planted leak: [`mul_base`] except that a zero digit skips its
    /// addition, the classic shortcut whose running time counts the
    /// scalar's nonzero digits. The table scan stays masked.
    fn mul_base_skipping_zero_digits(k: &[u8; 32]) -> Point {
        let t = tables();
        let mut acc = IDENTITY;
        for (i, row) in t.table.iter().enumerate() {
            let digit = u64::from((k[i / 2] >> (4 * (i % 2))) & 0x0f);
            let mut chosen = IDENTITY;
            for (j, entry) in row.iter().enumerate().skip(1) {
                let equal = ((digit ^ (j as u64)).wrapping_sub(1) >> 63) & 1;
                chosen = Point::select(&chosen, entry, 0u64.wrapping_sub(equal));
            }
            if digit != 0 {
                acc = acc.add(&chosen, &t.d2);
            }
        }
        acc
    }

    pub(crate) fn mul_base_skipping_zero_digits_x(k: &[u8; 32]) -> [u64; 5] {
        mul_base_skipping_zero_digits(k).x.0
    }

    /// The leaky variant is a correct one: the harness catches a timing
    /// difference, not a wrong answer.
    #[test]
    fn the_leaky_variant_computes_the_same_point() {
        let mut k = [0u8; 32];
        for round in 0u8..8 {
            for (i, b) in k.iter_mut().enumerate() {
                *b = round.wrapping_mul(37) ^ (i as u8).wrapping_mul(101);
            }
            k[usize::from(round)] = 0;
            assert_eq!(
                mul_base_skipping_zero_digits(&k).encode(),
                mul_base(&k).encode()
            );
        }
        assert_eq!(
            mul_base_skipping_zero_digits(&[0; 32]).encode(),
            IDENTITY.encode()
        );
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

    fn bytes(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 8032 §7.1, typed from the RFC: (secret key, public key, message,
    /// signature) for TEST 1, TEST 2, TEST 3 and TEST SHA(abc). Ed25519 is
    /// deterministic, so the signer must reproduce each signature exactly.
    const RFC8032: [(&str, &str, &str, &str); 4] = [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            "",
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
             5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            "72",
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
        (
            "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            "af82",
            "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
             18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        ),
        (
            "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
            "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b589
             09351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
        ),
    ];

    #[test]
    fn rfc8032_vectors_sign_exactly() {
        for (sk, pk, msg, sig) in RFC8032 {
            let key = SigningKey::from_seed(&unhex(sk));
            assert_eq!(key.public_key(), unhex::<32>(pk), "public key of {sk}");
            assert_eq!(key.sign(&bytes(msg)), unhex::<64>(sig), "signature of {sk}");
        }
    }

    /// The table and the masked selection agree with plain double-and-add
    /// on scalars that exercise every digit value.
    #[test]
    fn mul_base_matches_double_and_add() {
        let t = tables();
        let b = t.table[0][1];
        let slow = |k: &[u8; 32]| {
            let mut r = IDENTITY;
            for bit in (0..256).rev() {
                r = r.add(&r, &t.d2);
                if (k[bit / 8] >> (bit % 8)) & 1 == 1 {
                    r = r.add(&b, &t.d2);
                }
            }
            r
        };
        let mut k = [0u8; 32];
        for (i, x) in k.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(37) ^ 0xa5;
        }
        k[31] &= 0x7f;
        for _ in 0..4 {
            assert_eq!(mul_base(&k).encode(), slow(&k).encode());
            k.rotate_left(5);
            k[31] &= 0x7f;
        }
        // The base point encodes as y = 4/5 (0x58 0x66 …).
        let mut enc = [0x66u8; 32];
        enc[0] = 0x58;
        assert_eq!(b.encode(), enc);
    }

    /// The eight torsion points from the math, with this module's own
    /// arithmetic (independent of fa-verify's): [L]P is P's torsion
    /// component, and one of order 8 generates the subgroup.
    pub(crate) fn torsion_encodings() -> Vec<[u8; 32]> {
        let t = tables();
        let l = le_bytes(&L);
        let slow = |p: &Point, k: &[u8; 32]| {
            let mut r = IDENTITY;
            for bit in (0..256).rev() {
                r = r.add(&r, &t.d2);
                if (k[bit / 8] >> (bit % 8)) & 1 == 1 {
                    r = r.add(p, &t.d2);
                }
            }
            r
        };
        let is_identity = |p: &Point| p.x.to_bytes() == [0; 32] && p.y.to_bytes() == p.z.to_bytes();
        for y in 2u64..10_000 {
            let Some(p) = recover(&t.d, &t.sqrt_m1, Fe::small(y), 0) else {
                continue;
            };
            let gen8 = slow(&p, &l);
            let mut four = gen8;
            for _ in 0..2 {
                four = four.add(&four, &t.d2);
            }
            if is_identity(&four) {
                continue;
            }
            let mut out = Vec::new();
            let mut acc = IDENTITY;
            for _ in 0..8 {
                out.push(acc.encode());
                acc = acc.add(&gen8, &t.d2);
            }
            assert!(is_identity(&acc), "[8]T is the identity");
            out.sort_unstable();
            out.dedup();
            return out;
        }
        Vec::new() // never reached: the callers assert eight encodings
    }

    /// Ruling 3392: the producer's own trusted-key boundary refuses every
    /// small-order encoding (the identity among them, WhiteCreek's 3391
    /// candidate) and a non-canonical y, and admits generated keys.
    #[test]
    fn small_order_public_keys_are_refused() {
        let torsion = torsion_encodings();
        assert_eq!(torsion.len(), 8, "the eight torsion points");
        let mut identity = [0u8; 32];
        identity[0] = 1;
        assert!(torsion.contains(&identity));
        for t in &torsion {
            assert_eq!(check_public_key(t), Err(KeyError::SmallOrder));
        }
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(
            check_public_key(&p),
            Err(KeyError::NotAPoint),
            "y = p is not canonical"
        );
        for (sk, pk, _, _) in RFC8032 {
            assert_eq!(check_public_key(&unhex(pk)), Ok(()));
            assert_eq!(
                check_public_key(&SigningKey::from_seed(&unhex(sk)).public_key()),
                Ok(())
            );
        }
    }

    /// Reduction mod L: L ≡ 0, L + 7 ≡ 7, and (r + k·s) agrees with
    /// reducing the wide sum computed separately.
    #[test]
    fn scalar_arithmetic() {
        let mut wide = [0u8; 64];
        wide[..32].copy_from_slice(&le_bytes(&L));
        assert_eq!(reduce_512(&wide), [0; 4]);
        wide[0] += 7;
        assert_eq!(reduce_512(&wide), [7, 0, 0, 0]);
        // (L − 1) + 1·1 = L ≡ 0.
        let mut l_minus_1 = L;
        l_minus_1[0] -= 1;
        assert_eq!(
            mul_add_mod_l(&l_minus_1, &[1, 0, 0, 0], &[1, 0, 0, 0]),
            [0; 4]
        );
    }
}
