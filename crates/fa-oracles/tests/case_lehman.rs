//! The committed Lehman case at load time (docs/FORENSIC_CASE_STUDIES_PLAN.md
//! §8.3, §15 L3): each planted negative edits an in-memory copy of the
//! embedded case text and is decided by the check that owns it. The
//! committed files are never edited.

use fa_oracles::cases::check::run_load_checks;
use fa_oracles::cases::embedded::LEHMAN;
use fa_oracles::cases::error::LoadError;
use fa_oracles::cases::expect::ExpectationType;
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
