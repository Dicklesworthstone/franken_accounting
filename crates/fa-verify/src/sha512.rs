//! SHA-512 (FIPS 180-4), written from the specification for this crate
//! alone.
//!
//! Ed25519 (RFC 8032) hashes with SHA-512, and the verifier must be
//! auditable in isolation (plan §13.3), so it carries its own: the 80-round
//! compression function over 128-byte blocks, big-endian words, and the
//! 128-bit length padding. The round constants and the initial hash value
//! are copied from RFC 6234 §8.2.3 (FIPS 180-3 §4.2.3, §5.3.5); the tests
//! pin the RFC 6234 §8.5 vectors, whose expected digests are typed from the
//! RFC text, not produced by this code.

const H0: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

const K: [u64; 80] = [
    0x428A_2F98_D728_AE22,
    0x7137_4491_23EF_65CD,
    0xB5C0_FBCF_EC4D_3B2F,
    0xE9B5_DBA5_8189_DBBC,
    0x3956_C25B_F348_B538,
    0x59F1_11F1_B605_D019,
    0x923F_82A4_AF19_4F9B,
    0xAB1C_5ED5_DA6D_8118,
    0xD807_AA98_A303_0242,
    0x1283_5B01_4570_6FBE,
    0x2431_85BE_4EE4_B28C,
    0x550C_7DC3_D5FF_B4E2,
    0x72BE_5D74_F27B_896F,
    0x80DE_B1FE_3B16_96B1,
    0x9BDC_06A7_25C7_1235,
    0xC19B_F174_CF69_2694,
    0xE49B_69C1_9EF1_4AD2,
    0xEFBE_4786_384F_25E3,
    0x0FC1_9DC6_8B8C_D5B5,
    0x240C_A1CC_77AC_9C65,
    0x2DE9_2C6F_592B_0275,
    0x4A74_84AA_6EA6_E483,
    0x5CB0_A9DC_BD41_FBD4,
    0x76F9_88DA_8311_53B5,
    0x983E_5152_EE66_DFAB,
    0xA831_C66D_2DB4_3210,
    0xB003_27C8_98FB_213F,
    0xBF59_7FC7_BEEF_0EE4,
    0xC6E0_0BF3_3DA8_8FC2,
    0xD5A7_9147_930A_A725,
    0x06CA_6351_E003_826F,
    0x1429_2967_0A0E_6E70,
    0x27B7_0A85_46D2_2FFC,
    0x2E1B_2138_5C26_C926,
    0x4D2C_6DFC_5AC4_2AED,
    0x5338_0D13_9D95_B3DF,
    0x650A_7354_8BAF_63DE,
    0x766A_0ABB_3C77_B2A8,
    0x81C2_C92E_47ED_AEE6,
    0x9272_2C85_1482_353B,
    0xA2BF_E8A1_4CF1_0364,
    0xA81A_664B_BC42_3001,
    0xC24B_8B70_D0F8_9791,
    0xC76C_51A3_0654_BE30,
    0xD192_E819_D6EF_5218,
    0xD699_0624_5565_A910,
    0xF40E_3585_5771_202A,
    0x106A_A070_32BB_D1B8,
    0x19A4_C116_B8D2_D0C8,
    0x1E37_6C08_5141_AB53,
    0x2748_774C_DF8E_EB99,
    0x34B0_BCB5_E19B_48A8,
    0x391C_0CB3_C5C9_5A63,
    0x4ED8_AA4A_E341_8ACB,
    0x5B9C_CA4F_7763_E373,
    0x682E_6FF3_D6B2_B8A3,
    0x748F_82EE_5DEF_B2FC,
    0x78A5_636F_4317_2F60,
    0x84C8_7814_A1F0_AB72,
    0x8CC7_0208_1A64_39EC,
    0x90BE_FFFA_2363_1E28,
    0xA450_6CEB_DE82_BDE9,
    0xBEF9_A3F7_B2C6_7915,
    0xC671_78F2_E372_532B,
    0xCA27_3ECE_EA26_619C,
    0xD186_B8C7_21C0_C207,
    0xEADA_7DD6_CDE0_EB1E,
    0xF57D_4F7F_EE6E_D178,
    0x06F0_67AA_7217_6FBA,
    0x0A63_7DC5_A2C8_98A6,
    0x113F_9804_BEF9_0DAE,
    0x1B71_0B35_131C_471B,
    0x28DB_77F5_2304_7D84,
    0x32CA_AB7B_40C7_2493,
    0x3C9E_BE0A_15C9_BEBC,
    0x431D_67C4_9C10_0D4C,
    0x4CC5_D4BE_CB3E_42B6,
    0x597F_299C_FC65_7E2A,
    0x5FCB_6FAB_3AD6_FAEC,
    0x6C44_198C_4A47_5817,
];

const BLOCK_LEN: usize = 128;

fn compress(h: &mut [u64; 8], block: &[u8; BLOCK_LEN]) {
    let mut w = [0u64; 80];
    for (t, word) in block.as_chunks::<8>().0.iter().enumerate() {
        w[t] = u64::from_be_bytes(*word);
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for t in 0..80 {
        let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (x, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *x = x.wrapping_add(v);
    }
}

/// An incremental SHA-512.
#[derive(Clone)]
pub struct Sha512 {
    h: [u64; 8],
    block: [u8; BLOCK_LEN],
    filled: usize,
    /// Total message length in bytes (the padding encodes it in bits as a
    /// 128-bit integer).
    length: u128,
}

impl Default for Sha512 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha512 {
    #[must_use]
    pub fn new() -> Self {
        Self {
            h: H0,
            block: [0; BLOCK_LEN],
            filled: 0,
            length: 0,
        }
    }

    pub fn update(&mut self, mut input: &[u8]) -> &mut Self {
        self.length += input.len() as u128;
        while !input.is_empty() {
            let take = (BLOCK_LEN - self.filled).min(input.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&input[..take]);
            self.filled += take;
            input = &input[take..];
            if self.filled == BLOCK_LEN {
                compress(&mut self.h, &self.block);
                self.filled = 0;
            }
        }
        self
    }

    #[must_use]
    pub fn finalize(mut self) -> [u8; 64] {
        let bits = self.length.wrapping_mul(8);
        // 0x80, zeros, then the 16-byte big-endian bit length, ending on a
        // block boundary.
        self.block[self.filled] = 0x80;
        self.filled += 1;
        if self.filled > BLOCK_LEN - 16 {
            self.block[self.filled..].fill(0);
            compress(&mut self.h, &self.block);
            self.filled = 0;
        }
        self.block[self.filled..BLOCK_LEN - 16].fill(0);
        self.block[BLOCK_LEN - 16..].copy_from_slice(&bits.to_be_bytes());
        compress(&mut self.h, &self.block);
        let mut out = [0u8; 64];
        for (chunk, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(self.h) {
            *chunk = word.to_be_bytes();
        }
        out
    }
}

/// SHA-512 of the concatenation of `parts`.
#[must_use]
pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// RFC 6234 §8.5 (shatest.c), SHA-512 rows 1–4 and 6. The expected
    /// digests are the RFC's text.
    #[test]
    fn rfc6234_vectors() {
        let test2 = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                     hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let test4 = "0123456701234567012345670123456701234567012345670123456701234567";
        let cases: [(Vec<u8>, &str); 5] = [
            (
                b"abc".to_vec(),
                "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA2
                 0A9EEEE64B55D39A2192992A274FC1A836BA3C23A3FEEBBD
                 454D4423643CE80E2A9AC94FA54CA49F",
            ),
            (
                test2.as_bytes().to_vec(),
                "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA1
                 7299AEADB6889018501D289E4900F7E4331B99DEC4B5433A
                 C7D329EEB6DD26545E96E55B874BE909",
            ),
            (
                vec![b'a'; 1_000_000],
                "E718483D0CE769644E2E42C7BC15B4638E1F98B13B204428
                 5632A803AFA973EBDE0FF244877EA60A4CB0432CE577C31B
                 EB009C5C2C49AA2E4EADB217AD8CC09B",
            ),
            (
                test4.repeat(10).into_bytes(),
                "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024
                 DB872D1ABD2BA8141A0F85072A9BE1E2AA04CF33C765CB51
                 0813A39CD5A84C4ACAA64D3F3FB7BAE9",
            ),
            (
                vec![0xD0],
                "9992202938E882E73E20F6B69E68A0A7149090423D93C81B
                 AB3F21678D4ACEEEE50E4E8CAFADA4C85A54EA8306826C4A
                 D6E74CECE9631BFA8A549B4AB3FBBA15",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(
                sha512(&[&input]).to_vec(),
                unhex(expected),
                "{} bytes",
                input.len()
            );
        }
    }

    /// Splitting the input anywhere, including across the padding boundary
    /// at 112 bytes, does not change the digest.
    #[test]
    fn incremental_updates_equal_one_shot() {
        let data: Vec<u8> = (0..=300u16).map(|i| (i * 7 % 251) as u8).collect();
        for len in [0, 1, 111, 112, 113, 127, 128, 129, 239, 240, 256, 300] {
            let whole = sha512(&[&data[..len]]);
            for split in 0..=len {
                assert_eq!(
                    sha512(&[&data[..split], &data[split..len]]),
                    whole,
                    "{len}/{split}"
                );
            }
        }
    }
}
