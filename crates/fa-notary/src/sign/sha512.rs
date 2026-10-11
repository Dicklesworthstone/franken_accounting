//! SHA-512 (FIPS 180-4) for the interim Ed25519 signer.
//!
//! Interim (Appendix H R-SIGN): fgdb-crypto has no SHA-512 at the pinned
//! revision, and Ed25519 hashes with it. This is written separately from
//! fa-verify's (a rolling sixteen-word schedule here, a full eighty-word
//! one there) so the signer↔verifier differential compares two
//! implementations of one specification. Round constants and the initial
//! value are RFC 6234 §8.2.3's.

const IV: [u64; 8] = [
    0x6A09_E667_F3BC_C908,
    0xBB67_AE85_84CA_A73B,
    0x3C6E_F372_FE94_F82B,
    0xA54F_F53A_5F1D_36F1,
    0x510E_527F_ADE6_82D1,
    0x9B05_688C_2B3E_6C1F,
    0x1F83_D9AB_FB41_BD6B,
    0x5BE0_CD19_137E_2179,
];

const ROUND: [u64; 80] = [
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

/// One 128-byte block into the chaining state, with the message schedule
/// kept as a rolling window of sixteen words.
fn block(state: &mut [u64; 8], bytes: &[u8]) {
    let mut w = [0u64; 16];
    for (i, word) in w.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&bytes[8 * i..8 * i + 8]);
        *word = u64::from_be_bytes(b);
    }
    let mut v = *state;
    for (t, k) in ROUND.iter().enumerate() {
        if t >= 16 {
            let w15 = w[(t + 1) % 16];
            let w2 = w[(t + 14) % 16];
            let sigma0 = w15.rotate_right(1) ^ w15.rotate_right(8) ^ (w15 >> 7);
            let sigma1 = w2.rotate_right(19) ^ w2.rotate_right(61) ^ (w2 >> 6);
            w[t % 16] = w[t % 16]
                .wrapping_add(sigma0)
                .wrapping_add(w[(t + 9) % 16])
                .wrapping_add(sigma1);
        }
        let [a, b, c, d, e, f, g, h] = v;
        let t1 = h
            .wrapping_add(e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(*k)
            .wrapping_add(w[t % 16]);
        let t2 = (a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        v = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for (s, x) in state.iter_mut().zip(v) {
        *s = s.wrapping_add(x);
    }
}

/// SHA-512 of the concatenation of `parts`, padded in one pass at the end.
#[must_use]
pub fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut state = IV;
    let mut buf = [0u8; 128];
    let mut n = 0usize;
    let mut total: u128 = 0;
    for part in parts {
        total += part.len() as u128;
        for &byte in *part {
            buf[n] = byte;
            n += 1;
            if n == 128 {
                block(&mut state, &buf);
                n = 0;
            }
        }
    }
    buf[n] = 0x80;
    buf[n + 1..].fill(0);
    if n >= 112 {
        block(&mut state, &buf);
        buf = [0u8; 128];
    }
    buf[112..].copy_from_slice(&(total * 8).to_be_bytes());
    block(&mut state, &buf);
    let mut out = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        out[8 * i..8 * i + 8].copy_from_slice(&word.to_be_bytes());
    }
    fgdb_crypto::zeroize::scrub_slice(&mut buf);
    out
}

#[cfg(test)]
mod tests {
    use super::sha512;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02X}")).collect()
    }

    /// RFC 6234 §8.5, SHA-512 rows 1–4 and 6; expected digests typed from
    /// the RFC text.
    #[test]
    fn rfc6234_vectors() {
        let two = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                   hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
        let four = "01234567012345670123456701234567".repeat(20);
        let million = vec![b'a'; 1_000_000];
        let cases: [(&[u8], &str); 5] = [
            (
                b"abc",
                "DDAF35A193617ABACC417349AE20413112E6FA4E89A97EA20A9EEEE64B55D39A\
                 2192992A274FC1A836BA3C23A3FEEBBD454D4423643CE80E2A9AC94FA54CA49F",
            ),
            (
                two.as_bytes(),
                "8E959B75DAE313DA8CF4F72814FC143F8F7779C6EB9F7FA17299AEADB6889018\
                 501D289E4900F7E4331B99DEC4B5433AC7D329EEB6DD26545E96E55B874BE909",
            ),
            (
                &million,
                "E718483D0CE769644E2E42C7BC15B4638E1F98B13B2044285632A803AFA973EB\
                 DE0FF244877EA60A4CB0432CE577C31BEB009C5C2C49AA2E4EADB217AD8CC09B",
            ),
            (
                four.as_bytes(),
                "89D05BA632C699C31231DED4FFC127D5A894DAD412C0E024DB872D1ABD2BA814\
                 1A0F85072A9BE1E2AA04CF33C765CB510813A39CD5A84C4ACAA64D3F3FB7BAE9",
            ),
            (
                &[0xD0],
                "9992202938E882E73E20F6B69E68A0A7149090423D93C81BAB3F21678D4ACEEE\
                 E50E4E8CAFADA4C85A54EA8306826C4AD6E74CECE9631BFA8A549B4AB3FBBA15",
            ),
        ];
        for (input, expected) in cases {
            assert_eq!(hex(&sha512(&[input])), expected, "{} bytes", input.len());
        }
    }
}
