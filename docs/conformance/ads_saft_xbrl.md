# ADS-, SAF-T- and XBRL-Shaped Export Round-Trip Matrix

- **Oracle:** `fa-formats ADS-shaped, SAF-T-shaped and XBRL writers and readers (self round-trip)`
- **Proof Class:** `metamorphic (self round-trip) + summation check against a hand-written linkbase`
- **No-Claim Boundary:** Shows export-import round-trip identity through fa-formats' own writers and readers, coordinate certificate verification, FA-INV-04 refold equality, and summation consistency against XbrlCalculationLinkbase::standard_balance_sheet/standard_income_statement (written in this repository). No published AICPA ADS column set, OECD SAF-T XSD or XBRL taxonomy was used, so standards conformance is not claimed; that is fa-ipom.

| Fixture | Expected | Observed | Divergence | Reason |
|---|---|---|---|---|
| `aicpa_ads_gl_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' ADS-shaped export and its own re-import (asserted in aicpa_ads_and_oecd_saft_and_csv_gl_round_trip_identity_and_dropped_leg_negative). |
| `aicpa_ads_gl_v3_exact_text` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Exact canonical text and FA-INV-04 refold survive escaped delimiters, Unicode controls and absent versus empty optional fields (asserted in ads_v3_preserves_delimiters_controls_unicode_and_empty_optional_text); not an external AICPA escaping standard. |
| `oecd_saft_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' SAF-T-shaped XML export and its own re-import (asserted in the same test); no XSD validation. |
| `xbrl_us_gaap_bs_and_is_calc_linkbase` | `calc_parents_verified=4` | `calc_parents_verified=4` | `none` | Balance-sheet and income-statement summation arcs of the hand-written linkbase verify with zero discrepancy (asserted in xbrl_calculation_linkbase_validates_statements_and_catches_inconsistency); not a published taxonomy. |
