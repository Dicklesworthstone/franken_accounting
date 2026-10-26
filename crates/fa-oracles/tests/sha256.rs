//! fa-oracles' own SHA-256 against FIPS 180-4 and against digests computed
//! independently (Python's hashlib) at every padding boundary: a remainder
//! of 55 bytes pads in one block, 56 needs a second, 64 is one full block
//! plus a padding block, and 119/120 straddle the two-block boundary again.

#![forbid(unsafe_code)]

use fa_oracles::sha256::{self, FIPS_180_4_VECTORS, Message, Vector};

#[test]
fn sha256_matches_the_fips_180_4_vectors() {
    sha256::check_vectors(&FIPS_180_4_VECTORS).expect("every FIPS 180-4 vector");
    assert_eq!(
        FIPS_180_4_VECTORS.len(),
        5,
        "the five FIPS examples, none dropped"
    );
}

#[test]
fn sha256_check_fails_an_altered_vector() {
    let mut table = FIPS_180_4_VECTORS;
    // One hex digit of the "abc" digest changed: the check must fail and say
    // which vector, never pass or report another one.
    table[1] = Vector {
        digest_hex: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ae",
        ..table[1]
    };
    let err = sha256::check_vectors(&table).expect_err("an altered vector must fail");
    assert!(err.contains("`abc (one block)`"), "{err}");
    assert!(err.contains("computed ba7816bf"), "{err}");
}

#[test]
fn sha256_padding_boundaries_match_independent_digests() {
    // Digests of `a` repeated n times, computed with Python's hashlib.
    let cases: [(usize, &str); 9] = [
        (
            55,
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        ),
        (
            56,
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        ),
        (
            57,
            "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6",
        ),
        (
            63,
            "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34",
        ),
        (
            64,
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        ),
        (
            65,
            "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0",
        ),
        (
            119,
            "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb",
        ),
        (
            120,
            "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c",
        ),
        (
            128,
            "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e",
        ),
    ];
    for (n, want) in cases {
        let got = sha256::hex(&sha256::digest(&vec![b'a'; n]));
        assert_eq!(got, want, "{n} bytes of 'a'");
    }
}

#[test]
fn hex_is_lower_case_and_sixty_four_characters() {
    let d = sha256::digest(b"abc");
    let h = sha256::hex(&d);
    assert_eq!(h.len(), 64);
    assert!(
        h.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "{h}"
    );
    assert_eq!(
        Message::Repeat {
            byte: b'x',
            count: 3
        }
        .bytes(),
        b"xxx".to_vec()
    );
}
