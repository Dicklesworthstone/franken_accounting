# Beancount v3 & hledger Balance Differential Conformance Matrix

- **Oracle:** `beancount_v3 + hledger_journal`
- **Proof Class:** `differential (external oracle) + metamorphic (round-trip)`
- **No-Claim Boundary:** Agreement with Beancount and hledger proves exact per-account per-unit balance arithmetic agreement on the covered subset, not regulatory compliance.

| Fixture | Expected | Observed | Divergence | Reason |
|---|---|---|---|---|
| `genesis_single_currency_usd` | `1000:USD=+2500.00, 3000:USD=-2500.00` | `1000:USD=+2500.00, 3000:USD=-2500.00` | `none` | Exact per-account balance agreement across FrankenAccounting, Beancount v3, and hledger. |
| `acme_multi_unit_fy2026_p03` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:USD=-2500.00, 3000:EUR=-1000.00, 4000:USD=-755.00, 5000:USD=+182.50` | `1000:USD=+2500.00, 1010:EUR=+1000.00, 1200:USD=+755.00, 2000:USD=-182.50, 3000:USD=-2500.00, 3000:EUR=-1000.00, 4000:USD=-755.00, 5000:USD=+182.50` | `none` | Exact multi-currency native balance agreement across FrankenAccounting, Beancount v3, and hledger. |
| `fx_designated_leg_base_residual_eur_half_up` | `native EUR 0.01+0.01/0.02 balanced; base USD +0.01/+0.01/-0.02 with -0.01 designated-leg residual` | `Beancount @ price converts per-leg with tolerance and does not journal designated-leg base_residual` | `documented_rounding` | Plan §5.2 / §16.3: FrankenAccounting forbids tolerance auto-balancing and records exact designated-leg base_residual under a named RoundingLaw, whereas Beancount uses per-posting @ price tolerance. |
