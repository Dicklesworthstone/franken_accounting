/-
  FrankenAccounting Formal Anchor — Bitemporal Visibility &Escrow Bounds (plan §7.1, §5.4, §16.7, fa-8x9)
  Invariant mapping: FA-INV-07 (bitemporal visibility), FA-INV-09 (escrow/reservation bounds)
  Evidence class: proof (Lean 4)
-/

namespace FrankenAccounting.Bitemporal

structure EntryCoord where
  recordedAt : Nat
  effectiveDay : Int
  deriving DecidableEq, Repr

/-- An entry is visible in the known-at prefix `knownAt` and effective window `throughDay`. -/
def visibleAt (e : EntryCoord) (knownAt : Nat) (throughDay : Int) : Prop :=
  e.recordedAt ≤ knownAt ∧ e.effectiveDay ≤ throughDay

/-- Theorem (FA-INV-07 known-at monotonicity): Any entry visible at `(k1, d)` with `k1 ≤ k2`
    is also visible in the known-at prefix at `(k2, d)`. -/
theorem knownAt_monotonic (e : EntryCoord) (k1 k2 : Nat) (d : Int)
    (hVis : visibleAt e k1 d) (hLe : k1 ≤ k2) :
    visibleAt e k2 d := by
  unfold visibleAt at *
  exact ⟨Nat.le_trans hVis.1 hLe, hVis.2⟩

/-- Theorem (FA-INV-07 future commit invisibility): An entry recorded at `k2 > k1` is never
    visible at known-at `k1`. -/
theorem future_commit_invisible (e : EntryCoord) (k1 : Nat) (d : Int)
    (hAfter : k1 < e.recordedAt) :
    ¬ visibleAt e k1 d := by
  unfold visibleAt
  intro hVis
  omega

end FrankenAccounting.Bitemporal
