# AICPA ADS, OECD SAF-T & XBRL Conformance Matrix

- **Oracle:** `aicpa_ads_gl_v2 + oecd_saft_v2 + xbrl_gl_instance_v1`
- **Proof Class:** `metamorphic (export-import round-trip identity) + invariant (FA-INV-04 refold & XBRL calculation linkbase)`
- **No-Claim Boundary:** Proves deterministic export-import round-trip identity, coordinate certificate verification, FA-INV-04 refold equality, and XBRL calculation-linkbase summation consistency.

| Fixture | Expected | Observed | Divergence | Reason |
|---|---|---|---|---|
| `aicpa_ads_gl_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after AICPA ADS export and re-import. |
| `oecd_saft_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after OECD SAF-T v2.0 XML export and re-import. |
| `xbrl_us_gaap_bs_and_is_calc_linkbase` | `calc_parents_verified=4` | `calc_parents_verified=4` | `none` | All Balance Sheet and Income Statement XBRL summation-item calculation arcs verify with zero discrepancy. |
