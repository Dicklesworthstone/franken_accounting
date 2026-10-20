# Beancount v3 & hledger Self Round-Trip Matrix

- **Oracle:** `fa-formats beancount_v3 + hledger writers and readers (self round-trip)`
- **Proof Class:** `metamorphic (self round-trip); external tools not run`
- **No-Claim Boundary:** Shows that FrankenAccounting's fold survives its own Beancount v3 and hledger export read back by its own reader. bean-check and hledger did not evaluate these journals, so no agreement with either tool is claimed; that differential is fa-sa4w.

| Fixture | Expected | Observed | Divergence | Reason |
|---|---|---|---|---|
| `acme_multi_unit_fy2026_p03 via Beancount v3` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:EUR=-1000.00, 3000:USD=-2500.00, 4000:USD=-755.00, 5000:USD=+182.50` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:EUR=-1000.00, 3000:USD=-2500.00, 4000:USD=-755.00, 5000:USD=+182.50` | `none` | Written by fa-formats and read back by fa-formats; computed in this test. |
| `acme_multi_unit_fy2026_p03 via hledger` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:EUR=-1000.00, 3000:USD=-2500.00, 4000:USD=-755.00, 5000:USD=+182.50` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:EUR=-1000.00, 3000:USD=-2500.00, 4000:USD=-755.00, 5000:USD=+182.50` | `none` | Written by fa-formats and read back by fa-formats; computed in this test. |
| `fx_designated_leg_base_residual_eur_half_up` | `native EUR 0.01+0.01/0.02 balanced; base USD +0.01/+0.01/-0.02 with -0.01 designated-leg residual` | `not evaluated: bean-check was not run` | `not_run` | Plan §5.2 / §16.3 expect a divergence here (FrankenAccounting records the designated-leg base residual; Beancount documents per-posting @ price tolerance), but it has not been observed; fa-sa4w runs the tool. |
