//! The committed Lehman case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §8.3, §15 L3): each planted negative edits an in-memory copy of the
//! embedded case text and is decided by the check that owns it. The
//! committed files are never edited. Also the display band L-C-01's runner
//! line decides with ([`ratios`]), on synthetic integers.

use fa_oracles::cases::check::run_load_checks;
use fa_oracles::cases::embedded::LEHMAN;
use fa_oracles::cases::error::{LoadError, LoadErrorKind};
use fa_oracles::cases::expect::ExpectationType;
use fa_oracles::cases::ratios::{self, BandError};
use fa_oracles::cases::{Case, CaseFiles, load};

type Files = Vec<(&'static str, String)>;

fn lehman() -> Files {
    LEHMAN
        .files
        .iter()
        .map(|(path, text)| (*path, (*text).to_string()))
        .collect()
}

fn text_mut<'a>(files: &'a mut Files, file: &str) -> &'a mut String {
    &mut files
        .iter_mut()
        .find(|(p, _)| *p == file)
        .expect("a case file")
        .1
}

/// `old` replaced by `new` in `file`, where `old` occurs exactly `n` times,
/// so a stale plant never silently tests nothing.
fn plant(files: &mut Files, file: &str, old: &str, new: &str, n: usize) {
    let t = text_mut(files, file);
    assert_eq!(t.matches(old).count(), n, "plant `{old}` in {file}");
    *t = t.replace(old, new);
}

fn load_copy(files: &Files) -> Result<Case, Vec<LoadError>> {
    let view: Vec<(&str, &str)> = files.iter().map(|(p, t)| (*p, t.as_str())).collect();
    load(&CaseFiles {
        id: LEHMAN.id,
        files: &view,
    })
}

/// L-R-02 declared a T, with every field a T row needs (a T `kind`, its
/// vintages, a published fact on each target, and a T id, `L-T-09`, since
/// a T row of case L is `L-T-NN`), still reads back the (e) the scenario's
/// own intent posts: K-TAUT re-types each of its two reads R, the path
/// ending at that intent's leg, so it can never print as a T.
#[test]
fn lehman_l_r_02_declared_t_never_stays_t() {
    let mut files = lehman();
    plant(
        &mut files,
        "expectations.toml",
        "id = \"L-R-02\"\ntype = \"R\"\nbook_variant = \"statement\"\nstatement_template = \"R.read_back\"\n",
        "id = \"L-T-09\"\ntype = \"T\"\nbook_variant = \"statement\"\nstatement_template = \"T.per_account\"\nkind = \"per_account\"\nvintages = [\"source:SRC-LEH-001\"]\n",
        1,
    );
    plant(
        &mut files,
        "expectations.toml",
        "expectation = \"L-R-02\"",
        "expectation = \"L-T-09\"",
        2,
    );
    plant(&mut files, "case.toml", "\"L-R-02\"", "\"L-T-09\"", 1);
    // L-C-01's (e) term and detection limit read the renamed row.
    plant(
        &mut files,
        "expectations.toml",
        "L-R-02/V889-e-2008-05-31-inventory",
        "L-T-09/V889-e-2008-05-31-inventory",
        2,
    );
    plant(
        &mut files,
        "expectations.toml",
        "posted = \"V889-e-2008-05-31\"",
        "published = \"V889-e-2008-05-31\"",
        2,
    );
    let case = load_copy(&files).expect("the T copy loads");
    let retypes: Vec<_> = run_load_checks(&case)
        .into_iter()
        .flat_map(|r| r.retypes)
        .filter(|r| r.expectation == "L-T-09")
        .collect();
    let targets: Vec<Option<&str>> = retypes.iter().map(|r| r.target.as_deref()).collect();
    assert_eq!(
        targets,
        [
            Some("V889-e-2008-05-31-inventory"),
            Some("V889-e-2008-05-31-repos")
        ],
        "{retypes:?}"
    );
    for r in &retypes {
        assert_eq!(
            (r.from, r.to, r.check.as_str()),
            (ExpectationType::T, ExpectationType::R, "K-TAUT"),
            "{r}"
        );
        assert_eq!(
            r.path.first().map(String::as_str),
            Some("V889-e-2008-05-31"),
            "{r}"
        );
        assert!(
            r.path
                .last()
                .is_some_and(|p| p.starts_with("leg V889-e-2008-05-31#")),
            "{r}"
        );
    }
}

/// The committed L-R-02 is an R row with no re-type: its reads are the
/// scenario diff's, never a T's.
#[test]
fn lehman_committed_l_r_02_is_a_read_back() {
    let case = load_copy(&lehman()).expect("the committed case loads");
    let set = case.expectations.as_ref().expect("expectations");
    let row = set
        .expectations
        .iter()
        .find(|e| e.id == "L-R-02")
        .expect("L-R-02");
    assert_eq!(row.kind, ExpectationType::R);
    let reads: Vec<(&str, &str, &str)> = set
        .targets_of("L-R-02")
        .map(|t| {
            (
                t.fields.str("read_verb").unwrap_or_default(),
                t.fields.str("read_target").unwrap_or_default(),
                t.fields.str("read_selector").unwrap_or_default(),
            )
        })
        .collect();
    assert_eq!(
        reads,
        [
            ("scenario-diff", "1030", "scenario:lehman-repo105"),
            ("scenario-diff", "2030", "scenario:lehman-repo105"),
        ]
    );
    assert!(
        run_load_checks(&case)
            .iter()
            .flat_map(|r| &r.retypes)
            .all(|r| r.expectation != "L-R-02")
    );
}

/// 13.9x is 139 at one place; its 0.1x display unit is 1 there.
fn band(num: i128, den: i128, printed: i128) -> Result<ratios::Band, BandError> {
    ratios::within_display_band(num, den, printed, 1, 1)
}

#[test]
fn band_exact_printed_value_passes() {
    let b = band(1_390, 100, 139).expect("a verdict");
    assert!(b.within);
    assert_eq!((b.distance, b.limit), (0, 100));
}

/// The plan's test is ≤ one display unit: both edges pass.
#[test]
fn band_edges_are_inclusive() {
    for num in [1_380, 1_400] {
        let b = band(num, 100, 139).expect("a verdict");
        assert!(b.within, "{num}");
        assert_eq!(b.distance, 100, "{num}");
    }
}

#[test]
fn band_one_past_edge_fails() {
    for num in [1_379, 1_401] {
        let b = band(num, 100, 139).expect("a verdict");
        assert!(!b.within, "{num}");
        assert_eq!(b.distance, 110, "{num}");
    }
}

#[test]
fn band_planted_printed_13_7_fails() {
    let b = band(1_390, 100, 137).expect("a verdict");
    assert!(!b.within);
    assert_eq!(b.distance, 200);
}

/// With (b) = 1,290 and (d) = 100, the band accepts e from 90 to 110.
#[test]
fn band_detection_interval() {
    assert_eq!(
        ratios::detection_interval(1_290, 100, 139, 1, 1),
        Ok((90, 110))
    );
    // A fractional edge rounds inward: (138·33)/10 = 455.4 and (140·33)/10 = 462.
    assert_eq!(ratios::detection_interval(0, 33, 139, 1, 1), Ok((456, 462)));
}

#[test]
fn band_non_positive_den_refused() {
    for den in [0, -100] {
        assert_eq!(
            band(1_390, den, 139),
            Err(BandError::NonPositiveDenominator)
        );
        assert_eq!(
            ratios::detection_interval(1_290, den, 139, 1, 1),
            Err(BandError::NonPositiveDenominator)
        );
    }
}

#[test]
fn band_overflow_refused() {
    assert_eq!(band(i128::MAX, 100, 139), Err(BandError::Overflow));
    assert_eq!(band(1_390, i128::MAX, 139), Err(BandError::Overflow));
    assert_eq!(
        ratios::detection_interval(0, i128::MAX, 139, 1, 1),
        Err(BandError::Overflow)
    );
}

/// The committed L-C-01 is a C row whose numerator reads the certified
/// footing, the four read-back deductions and the scenario diff's (e), over
/// (d) as p.889 prints it, with (e)'s read as its detection term.
#[test]
fn lehman_committed_l_c_01_computes_from_certified_reads() {
    let case = load_copy(&lehman()).expect("the committed case loads");
    let set = case.expectations.as_ref().expect("expectations");
    let row = set.get("L-C-01").expect("L-C-01");
    assert_eq!(row.kind, ExpectationType::C);
    let num = row.fields.strs("numerator").expect("a numerator");
    assert_eq!(num.len(), 6);
    assert!(num.iter().all(|t| !t.contains("fact:")), "{num:?}");
    assert_eq!(
        row.fields.strs("denominator"),
        Some(&["+fact:V889-d-2008-05-31".to_string()][..])
    );
    assert_eq!(
        row.fields.str("detection_limit"),
        Some("L-R-02/V889-e-2008-05-31-inventory")
    );
}

/// L-C-01 declared a T is refused at load: its C fields are not T fields
/// and a T row of case L is `L-T-NN`, so it can never print as a T.
#[test]
fn lehman_l_c_01_declared_t_never_passes() {
    let mut files = lehman();
    plant(
        &mut files,
        "expectations.toml",
        "id = \"L-C-01\"\ntype = \"C\"",
        "id = \"L-C-01\"\ntype = \"T\"",
        1,
    );
    let errs = load_copy(&files).expect_err("refused");
    assert!(
        errs.iter()
            .any(|e| e.file == "expectations.toml" && e.row.as_deref() == Some("L-C-01")),
        "{errs:?}"
    );
}

/// A C term naming no read of the variant, or a detection limit naming no
/// numerator term, is refused at load.
#[test]
fn lehman_c_term_and_detection_limit_must_resolve() {
    let mut files = lehman();
    plant(
        &mut files,
        "expectations.toml",
        "\"-L-R-01/Q208.intangibles.2008-05-31\"",
        "\"-L-R-01/Q208.goodwill.2008-05-31\"",
        1,
    );
    plant(
        &mut files,
        "expectations.toml",
        "detection_limit = \"L-R-02/V889-e-2008-05-31-inventory\"",
        "detection_limit = \"L-R-02/V889-e-2008-05-31-repos\"",
        1,
    );
    let errs = load_copy(&files).expect_err("refused");
    for needle in [
        "numerator term `-L-R-01/Q208.goodwill.2008-05-31`: `L-R-01` has no read",
        "`detection_limit = \"L-R-02/V889-e-2008-05-31-repos\"` is not a numerator term's ref",
    ] {
        assert!(
            errs.iter()
                .any(|e| e.kind == LoadErrorKind::DanglingKey && e.detail.contains(needle)),
            "{needle}: {errs:?}"
        );
    }
}
