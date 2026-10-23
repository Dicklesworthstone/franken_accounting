# ADS-, SAF-T- and XBRL-Shaped Export Round-Trip Matrix

- **Oracle:** `fa-formats ADS-shaped, SAF-T-shaped and XBRL writers and readers (self round-trip)`
- **Proof Class:** `metamorphic (self round-trip) + summation check against a hand-written linkbase`
- **No-Claim Boundary:** Shows export-import round-trip identity through fa-formats' own writers and readers, coordinate certificate verification, FA-INV-04 refold equality, and summation consistency against XbrlCalculationLinkbase::standard_balance_sheet/standard_income_statement (written in this repository). No published AICPA ADS column set, OECD SAF-T XSD or XBRL taxonomy was used, so standards conformance is not claimed; that is fa-ipom.

## ADS text versions (fa-8kpw)

The writer retains literal `aicpa_ads_gl_v2` bytes for representable ordinary
text. Text containing pipes, backslashes, quotes or control characters selects
`aicpa_ads_gl_v3`, named explicitly in the coordinate certificate. Both versions
remain readable. This is this repository's ADS-shaped profile, not a claim about
an external AICPA escaping standard.

In v3 every table text field uses `\\` for a backslash, `\p` for a pipe,
`\n` and `\r` for line endings, and `\u` followed by four lowercase hex digits
for other Unicode control characters. Every other character remains literal.
Noncanonical and unknown escapes are refused. In GL_Detail's two optional text
columns, the whole field `\N` means absent; an empty field means present but
empty. Literal `\N` text therefore starts with an escaped backslash. Coordinate
names use `book_name_utf8_hex` and `base_unit_code_utf8_hex`, preserving UTF-8
without depending on the small TOML parser's supported escape subset.

The same text law applies to identifiers in the chart, GL and trial balance.
The std-only offline verifier has its own decoder and continues to verify the
same proven selection, accounts, units, amounts and trial-balance refold. It
does not authenticate description/memo text or chart names; escaping does not
raise that proof class. New v3 regressions are authored in
`ads_v3_preserves_delimiters_controls_unicode_and_empty_optional_text` and
`ads_text_survives_real_post_export_reimport_and_offline_verification`; their
current-source execution status must be taken from the corresponding gate,
not from this format description.

| Fixture | Expected | Observed | Divergence | Reason |
|---|---|---|---|---|
| `aicpa_ads_gl_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' ADS-shaped export and its own re-import (asserted in aicpa_ads_and_oecd_saft_and_csv_gl_round_trip_identity_and_dropped_leg_negative). |
| `oecd_saft_v2_acme_fy2026_p03` | `round_trip_identity=true, refold_equal=true` | `round_trip_identity=true, refold_equal=true` | `none` | Byte-identical FormatJournal and FA-INV-04 refold digest after fa-formats' SAF-T-shaped XML export and its own re-import (asserted in the same test); no XSD validation. |
| `xbrl_us_gaap_bs_and_is_calc_linkbase` | `calc_parents_verified=4` | `calc_parents_verified=4` | `none` | Balance-sheet and income-statement summation arcs of the hand-written linkbase verify with zero discrepancy (asserted in xbrl_calculation_linkbase_validates_statements_and_catches_inconsistency); not a published taxonomy. |
