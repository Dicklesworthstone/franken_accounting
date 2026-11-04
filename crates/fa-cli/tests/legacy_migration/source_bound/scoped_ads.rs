//! A real retained-source import through account-scoped ADS export. The
//! partial source population stays invisible at its historical checkpoint;
//! its finalized population is proved with native source-bound balances.

use super::*;

struct Package {
    certificate: String,
    chart: String,
    gl: String,
    tb: String,
    bundle: Vec<u8>,
    receipt: Vec<u8>,
}

impl Package {
    fn export(fixture: &Fixture, state: &str, name: &str) -> Self {
        let directory = fixture.dir.join(name);
        let exported = ok(
            &fixture.book,
            &[
                "export",
                "ads",
                "--account",
                "1000",
                "--as-of",
                "2026-12-31",
                "--state",
                state,
                "--with-proofs",
                "--out",
                directory.to_str().unwrap(),
            ],
        );
        assert_eq!(text(&exported, "event"), "journal_exported");
        let text = |name| std::fs::read_to_string(directory.join(name)).unwrap();
        Self {
            certificate: text("ADS_Coordinate_Certificate.toml"),
            chart: text("Chart_of_Accounts.txt"),
            gl: text("GL_Detail.txt"),
            tb: text("Trial_Balance.txt"),
            bundle: std::fs::read(directory.join("ADS_Proof.fab")).unwrap(),
            receipt: std::fs::read(directory.join("ADS_Proof.receipt")).unwrap(),
        }
    }

    fn verify(&self, key: [u8; 32]) -> fa_verify::ads::AdsReport {
        fa_verify::ads::verify_ads(
            &self.certificate,
            &self.chart,
            &self.gl,
            &self.tb,
            &self.bundle,
            &[key],
            Some(&self.receipt),
        )
        .unwrap()
    }
}

#[test]
fn source_bound_account_ads_proves_partial_and_finalized_populations_and_rejects_manifest_tampering()
 {
    let fixture = Fixture::quickbooks();
    let prepared = prepare_bound(&fixture);
    let package_oid = text(data(&prepared), "package_oid");
    let approved = approvals(&fixture, &prepared);
    assert_eq!(approved.len(), 2);
    let partial = stage_group(&fixture, package_oid, &[0], &approved);
    assert_eq!(
        data(&partial).get("ready_to_finalize"),
        Some(&Json::Bool(false))
    );
    let staged = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let completed = stage_group(&fixture, package_oid, &[0, 1], &approved);
    assert_eq!(
        data(&completed).get("ready_to_finalize"),
        Some(&Json::Bool(true))
    );
    fixture.finalize("scoped-ads-source-finalize.plan");
    let finalized = ok(
        &fixture.book,
        &["checkpoint", "create", "--grant", "witness"],
    );
    let book = fixture.open();
    let key = book.checkpoint_public_key();
    let manifest = book
        .migration_source_manifest(run_id(&fixture), None)
        .unwrap()
        .unwrap();
    assert_eq!(manifest.chunks.len(), 2);
    let manifest_bytes = manifest.canonical_bytes().unwrap();
    drop(book);

    let hidden = Package::export(&fixture, text(data(&staged), "oid"), "source-ads-partial");
    let visible = Package::export(&fixture, text(data(&finalized), "oid"), "source-ads-final");
    for (exported, count) in [(&hidden, 0), (&visible, 2)] {
        let judged = exported.verify(key);
        assert!(judged.verified(), "{:?}", judged.failures);
        assert_eq!((judged.entries, judged.rows), (count, count * 2));
        assert_eq!(judged.tb_rows, u64::from(count != 0));
        assert_eq!(judged.account_scope.as_deref(), Some("1000"));
        assert_eq!(judged.bundle.summary.format, (1, 2));
        assert_eq!(judged.bundle.summary.balances.len(), 1);
        assert_eq!(judged.chart_rows, None);
        assert!(
            exported
                .bundle
                .windows(b"fa:acc-balance-proof:v4".len())
                .any(|w| w == b"fa:acc-balance-proof:v4")
        );
        assert!(
            exported
                .bundle
                .windows(manifest_bytes.len())
                .any(|w| w == manifest_bytes)
        );
    }
    assert!(
        visible.tb.contains("1000|2026-12-31|D|125.50|USD|2"),
        "{}",
        visible.tb
    );
    let replay = Package::export(
        &fixture,
        text(data(&staged), "oid"),
        "source-ads-partial-again",
    );
    assert_eq!(
        replay.bundle, hidden.bundle,
        "later finalization never changes the selected proof state"
    );

    // Swap only the authenticated source member digest. Omitting the outer
    // receipt deliberately isolates source-bound recomputation failure from
    // the simpler detached-receipt digest check.
    let mut changed = visible.bundle.clone();
    let at = changed
        .windows(manifest_bytes.len())
        .position(|w| w == manifest_bytes)
        .unwrap();
    changed[at + manifest_bytes.len() - 1] ^= 1;
    let rejected = fa_verify::ads::verify_ads(
        &visible.certificate,
        &visible.chart,
        &visible.gl,
        &visible.tb,
        &changed,
        &[key],
        None,
    )
    .unwrap();
    assert!(!rejected.verified());
    assert!(
        rejected
            .bundle
            .checks
            .iter()
            .any(|check| check.check == "recomputation"
                && matches!(check.grade, fa_verify::bundle::Grade::Fail(_))),
        "{:?}",
        rejected.bundle.checks
    );

    // A valid staged-state bundle cannot attest the finalized extract's rows.
    let smuggled = fa_verify::ads::verify_ads(
        &hidden.certificate,
        &hidden.chart,
        &visible.gl,
        &hidden.tb,
        &hidden.bundle,
        &[key],
        Some(&hidden.receipt),
    )
    .unwrap();
    assert!(smuggled.bundle.verified());
    assert!(!smuggled.verified());
    assert!(
        smuggled
            .failures
            .iter()
            .any(|failure| failure.contains("is no proven entry")),
        "{:?}",
        smuggled.failures
    );
}
