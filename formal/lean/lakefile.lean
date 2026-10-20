import Lake
open Lake DSL

package «franken_accounting_formal» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩
  ]

@[default_target]
lean_lib «FrankenAccounting» where
  roots := #[`FrankenAccounting]
